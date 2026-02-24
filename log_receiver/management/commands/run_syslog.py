"""
Syslog Receiver — Arquitetura Pipeline para alta escala (80+ FortiGates).

Fluxo:
  [UDP socket]
      │ enqueue_raw (non-blocking, < 1µs)
      ▼
  _raw_queue  (maxsize=20000 raw strings)
      │
  [Worker Pool — 8 threads]
      │ parse + route
      ▼
  [DB Writers]  — SecurityEvent, VPNLog, VPNFailure via bulk_create
      │
  [Device Throttle] — 1 update/min por device via _device_queue

Capacidade estimada:
  80 FortiGates × 20 pkt/s = 1600 pkt/s
  Pool de 8 workers: 200 pkt/s por worker → ok para MSSQL (50-100 inserts/s por thread)
"""

import logging
import socketserver
import threading
import queue
import time

from django.core.management.base import BaseCommand
from log_receiver.parsers.fortinet import parse_fortinet_syslog

logger = logging.getLogger(__name__)

# ─────────────────────────────────────────────────────────────────────────────
#  Filas e configurações globais
# ─────────────────────────────────────────────────────────────────────────────

# Fila principal: raw (ip, data_str) — recepção ultra-rápida
_raw_queue = queue.Queue(maxsize=20000)

# Fila de dispositivos (baixo volume pós-throttle)
_device_queue = queue.Queue(maxsize=500)

# Throttle: 1 update/min por device_id
_device_last_seen: dict = {}
_device_throttle_lock = threading.Lock()
DEVICE_THROTTLE_SECONDS = 60

# Número de workers de processamento
NUM_WORKERS = 8

# Tamanho do batch para bulk_create de SecurityEvents
BATCH_SIZE = 50
BATCH_FLUSH_INTERVAL = 2.0  # segundos máximo antes de flush mesmo sem completar o batch


# ─────────────────────────────────────────────────────────────────────────────
#  Workers
# ─────────────────────────────────────────────────────────────────────────────

def _device_db_worker():
    """Persiste KnownDevice com retry — volume baixo graças ao throttle."""
    from django import db
    while True:
        try:
            item = _device_queue.get(timeout=5)
            if item is None:
                break
            devid, devname, ip = item
            db.connections.close_all()
            from integrations.models import KnownDevice
            from django.utils import timezone
            try:
                KnownDevice.objects.update_or_create(
                    device_id=devid,
                    defaults={'hostname': devname, 'ip_address': ip, 'last_seen': timezone.now()}
                )
            except Exception as e:
                logger.warning(f"Device save failed for {devid}: {e}")
            finally:
                _device_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Device worker error: {e}")
            time.sleep(1)


def _log_processor_worker(worker_id: int):
    """
    Consome (ip, raw_str) da _raw_queue, parseia e grava no banco.
    Cada worker tem sua própria conexão Django.
    SecurityEvents são acumulados em micro-batch antes do flush.
    """
    from django import db
    from security_events.models import SecurityEvent

    batch_buffer: list = []
    last_flush = time.time()

    def flush_batch():
        nonlocal batch_buffer, last_flush
        if not batch_buffer:
            return
        try:
            db.connections.close_all()
            # MSSQL não suporta ignore_conflicts — deduplica via query prévia
            ids_no_batch = [obj.event_id for obj in batch_buffer]
            ja_existentes = set(
                SecurityEvent.objects.filter(event_id__in=ids_no_batch)
                .values_list('event_id', flat=True)
            )
            novos = [obj for obj in batch_buffer if obj.event_id not in ja_existentes]
            if novos:
                SecurityEvent.objects.bulk_create(novos)
                logger.debug(f"[W{worker_id}] bulk_create: {len(novos)} novos | {len(batch_buffer)-len(novos)} ignorados")
        except Exception as e:
            logger.error(f"[W{worker_id}] bulk_create failed: {e}")
            # Fallback: salva um a um
            for obj in batch_buffer:
                try:
                    obj.save()
                except Exception:
                    pass
        batch_buffer = []
        last_flush = time.time()

    while True:
        try:
            # Coleta com timeout para garantir flush periódico
            try:
                item = _raw_queue.get(timeout=BATCH_FLUSH_INTERVAL)
            except queue.Empty:
                flush_batch()
                continue

            if item is None:
                flush_batch()
                break

            ip, raw_data = item
            try:
                parsed = parse_fortinet_syslog(raw_data)
                log_type = parsed.get('type', '')
                subtype  = parsed.get('subtype', '')

                # --- Eventos VPN ---
                if log_type == 'event' and subtype == 'vpn':
                    action = parsed.get('action', '')
                    if action in ['negotiate-error', 'auth-failure', 'ssl-login-fail', 'ipsec-login-fail']:
                        _save_vpn_failure(parsed, ip)
                    elif action in ['tunnel-up', 'tunnel-down', 'ssl-new-session', 'ssl-exit']:
                        _save_vpn_log(parsed)

                # --- UTM events ---
                elif log_type == 'utm' or (log_type == 'traffic' and parsed.get('utm-action')):
                    se = _build_security_event(parsed, raw_data)
                    if se:
                        batch_buffer.append(se)

                # --- System Alerts ---
                elif log_type == 'event' and (subtype in ['system', 'link']):
                    _process_system_alert(parsed)

            except Exception as e:
                logger.error(f"[W{worker_id}] parse error from {ip}: {e}")
            finally:
                _raw_queue.task_done()

            # Flush se cheio ou tempo expirou
            if len(batch_buffer) >= BATCH_SIZE or (time.time() - last_flush) >= BATCH_FLUSH_INTERVAL:
                flush_batch()

        except Exception as e:
            logger.error(f"[W{worker_id}] unhandled error: {e}")
            time.sleep(0.5)


# ─────────────────────────────────────────────────────────────────────────────
#  Funções de parse e construção de objetos
# ─────────────────────────────────────────────────────────────────────────────

def parse_fortinet_timestamp(parsed_data):
    """Timestamp usando eventtime (ns) → date+time+tz → agora."""
    from django.utils import timezone as dj_tz
    import datetime

    eventtime_ns = parsed_data.get('eventtime', '')
    tz_str = parsed_data.get('tz', '-0300')
    try:
        if eventtime_ns and len(str(eventtime_ns)) > 15:
            ts_sec = int(eventtime_ns) / 1e9
            dt_utc = datetime.datetime.utcfromtimestamp(ts_sec).replace(tzinfo=datetime.timezone.utc)
            return dj_tz.make_aware(dt_utc.astimezone(
                dj_tz.get_current_timezone()
            ).replace(tzinfo=None))
    except Exception:
        pass

    try:
        from dateutil.parser import parse as dateparse
        dt = dateparse(f"{parsed_data.get('date', '')} {parsed_data.get('time', '')}")
        return dj_tz.make_aware(dt) if dj_tz.is_naive(dt) else dt
    except Exception:
        return dj_tz.now()


def map_severity(level_str):
    level = level_str.lower()
    return {
        'critical': 'critical', 'alert': 'critical', 'emergency': 'critical',
        'error': 'high',
        'warning': 'medium', 'warn': 'medium',
        'notice': 'low',
    }.get(level, 'info')


def _int(value, default=None):
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _build_security_event(parsed_data, raw_data):
    """Constrói (sem salvar) um objeto SecurityEvent rico com todos os campos."""
    import hashlib, json, urllib.parse
    from security_events.models import SecurityEvent

    SUBTYPE_MAP = {
        'webfilter': 'webfilter', 'app-ctrl': 'app-control',
        'appctrl': 'app-control', 'ips': 'ips',
        'virus': 'antivirus', 'dlp': 'webfilter',
    }
    fa_subtype  = parsed_data.get('subtype', '')
    mapped_type = SUBTYPE_MAP.get(fa_subtype)
    if not mapped_type:
        return None

    log_str      = json.dumps(parsed_data, sort_keys=True)
    event_id_raw = hashlib.md5(log_str.encode()).hexdigest()

    if SecurityEvent.objects.filter(event_id=event_id_raw).exists():
        return None

    timestamp = parse_fortinet_timestamp(parsed_data)
    src_ip    = parsed_data.get('srcip', '0.0.0.0')
    dst_ip    = parsed_data.get('dstip', '0.0.0.0')
    username  = parsed_data.get('user', '')
    action    = parsed_data.get('action', '')
    severity  = map_severity(parsed_data.get('level', ''))

    kwargs = dict(
        event_id=event_id_raw, event_type=mapped_type, severity=severity,
        timestamp=timestamp, date=timestamp.date(),
        src_ip=src_ip, dst_ip=dst_ip,
        username=username, action=action, raw_log=log_str,
        src_port=_int(parsed_data.get('srcport')),
        dst_port=_int(parsed_data.get('dstport')),
    )

    if mapped_type == 'ips':
        kwargs.update(
            attack_name=parsed_data.get('attack', parsed_data.get('attackname', '')),
            attack_id=parsed_data.get('attackid', ''),
            cve=parsed_data.get('cve', ''),
            src_country=urllib.parse.unquote(parsed_data.get('srccountry', '')),
        )
    elif mapped_type == 'antivirus':
        kwargs.update(
            virus_name=parsed_data.get('virus', ''),
            file_name=parsed_data.get('filename', parsed_data.get('fname', '')),
            file_hash=parsed_data.get('checksum', ''),
            url=urllib.parse.unquote(parsed_data.get('url', '')),
        )
    elif mapped_type == 'webfilter':
        kwargs.update(
            url=urllib.parse.unquote(parsed_data.get('url', '')),
            category=urllib.parse.unquote(parsed_data.get('catdesc', parsed_data.get('category', ''))),
            src_country=urllib.parse.unquote(parsed_data.get('srccountry', '')),
        )
    elif mapped_type == 'app-control':
        kwargs.update(
            app_name=urllib.parse.unquote(parsed_data.get('app', '')),
            app_category=urllib.parse.unquote(parsed_data.get('appcat', '')),
            app_risk=parsed_data.get('apprisk', ''),
            bytes_in=_int(parsed_data.get('rcvdbyte')),
            bytes_out=_int(parsed_data.get('sentbyte')),
        )

    return SecurityEvent(**kwargs)


def _save_vpn_failure(parsed_data, ip):
    from vpn_logs.models import VPNFailure
    username  = parsed_data.get('user', 'unknown')
    source_ip = parsed_data.get('remip', parsed_data.get('srcip', ip))
    reason    = parsed_data.get('reason', parsed_data.get('action', ''))
    ts        = parse_fortinet_timestamp(parsed_data)
    if not VPNFailure.objects.filter(user=username, source_ip=source_ip, timestamp=ts).exists():
        VPNFailure.objects.create(
            user=username, source_ip=source_ip,
            timestamp=ts, reason=reason,
            country_code='', city='', raw_data=parsed_data
        )


def _save_vpn_log(parsed_data):
    from vpn_logs.models import VPNLog
    session_id = parsed_data.get('sessionid', parsed_data.get('tunnelid', ''))
    if not session_id:
        return
    username  = parsed_data.get('user', 'unknown')
    source_ip = parsed_data.get('remip', parsed_data.get('srcip', '0.0.0.0'))
    action    = parsed_data.get('action', '')
    ts        = parse_fortinet_timestamp(parsed_data)

    if action in ['tunnel-up', 'ssl-new-session']:
        if not VPNLog.objects.filter(session_id=session_id).exists():
            VPNLog.objects.create(
                session_id=session_id, user=username,
                source_ip=source_ip, start_time=ts,
                status=action, raw_data=parsed_data
            )
    elif action in ['tunnel-down', 'ssl-exit']:
        vpn_log = VPNLog.objects.filter(session_id=session_id).first()
        if vpn_log:
            vpn_log.end_time      = ts
            vpn_log.status        = action
            vpn_log.bandwidth_out = _int(parsed_data.get('sentbyte'), 0)
            vpn_log.bandwidth_in  = _int(parsed_data.get('rcvdbyte'), 0)
            if vpn_log.start_time:
                vpn_log.duration = int((ts - vpn_log.start_time).total_seconds())
            vpn_log.save()


def _process_system_alert(parsed_data):
    """Detecta alertas críticos de sistema (CPU, Memória, Link) e atualiza o KnownDevice."""
    devid = parsed_data.get('devid')
    if not devid:
        return

    msg = parsed_data.get('msg', '').lower()
    
    update_fields = {}
    alert = None

    # Lógica de detecção de strings comuns de alarmes Fortigate
    if 'cpu' in msg and ('limit' in msg or 'high' in msg or 'exhaustion' in msg):
        alert = f"CPU Alta: {parsed_data.get('msg')}"
        update_fields['cpu_status'] = 'alto'
    elif 'mem' in msg and ('limit' in msg or 'high' in msg or 'exhaustion' in msg):
        alert = f"Memória Alta: {parsed_data.get('msg')}"
        update_fields['memory_status'] = 'alto'
    elif 'conserve' in msg:
        alert = f"Conserve Mode: {parsed_data.get('msg')}"
        update_fields['conserve_mode'] = True
        update_fields['memory_status'] = 'alto'
    elif 'link' in msg and ('down' in msg or 'fail' in msg or 'alarm' in msg):
        alert = f"Link Down/Alarm: {parsed_data.get('msg')}"
        update_fields['link_status'] = 'alarme'

    if alert or update_fields:
        from integrations.models import KnownDevice
        from django.utils import timezone
        
        if alert:
            update_fields['last_alert_message'] = alert
            update_fields['last_alert_time'] = timezone.now()

        # Atualiza diretamente via queryset para ser atômico e rápido
        KnownDevice.objects.filter(device_id=devid).update(**update_fields)


# ─────────────────────────────────────────────────────────────────────────────
#  Handler UDP — apenas enfileira, não processa
# ─────────────────────────────────────────────────────────────────────────────

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw   = self.request[0]
        ip    = self.client_address[0]
        data  = raw.strip().decode('utf-8', errors='ignore')

        # 1. Detectar device com throttle (baixíssimo custo)
        try:
            parsed_quick = parse_fortinet_syslog(data)
            devid   = parsed_quick.get('devid', f'UNKNOWN-{ip}')
            devname = parsed_quick.get('devname', f'Device at {ip}')
            with _device_throttle_lock:
                last = _device_last_seen.get(devid, 0)
                now  = time.time()
                if now - last >= DEVICE_THROTTLE_SECONDS:
                    _device_last_seen[devid] = now
                    try:
                        _device_queue.put_nowait((devid, devname, ip))
                    except queue.Full:
                        pass
        except Exception:
            pass

        # 2. Enfileira raw para processamento assíncrono
        try:
            _raw_queue.put_nowait((ip, data))
        except queue.Full:
            logger.warning(f"Raw queue full — dropping packet from {ip}")


# ─────────────────────────────────────────────────────────────────────────────
#  Management Command
# ─────────────────────────────────────────────────────────────────────────────

class Command(BaseCommand):
    help = 'Inicia o Syslog Receiver de alta performance (pipeline + worker pool)'

    def handle(self, *args, **options):
        HOST, PORT = "0.0.0.0", 5140

        self.stdout.write(self.style.SUCCESS(
            f'Syslog Receiver iniciando em {HOST}:{PORT}/UDP | '
            f'{NUM_WORKERS} workers | batch={BATCH_SIZE} | '
            f'device throttle={DEVICE_THROTTLE_SECONDS}s'
        ))

        # Inicia worker de dispositivos (1 thread)
        threading.Thread(target=_device_db_worker, daemon=True, name="device-worker").start()

        # Inicia pool de workers de log
        for i in range(NUM_WORKERS):
            threading.Thread(
                target=_log_processor_worker,
                args=(i,),
                daemon=True,
                name=f"log-worker-{i}"
            ).start()

        # Monitor de saúde (imprime stats a cada 60s)
        def _monitor():
            while True:
                time.sleep(60)
                logger.info(
                    f"[MONITOR] raw_queue={_raw_queue.qsize()} "
                    f"device_queue={_device_queue.qsize()} "
                    f"known_devices={len(_device_last_seen)}"
                )
        threading.Thread(target=_monitor, daemon=True, name="monitor").start()

        # Servidor UDP — preempt_socket desativado para não bloquear no GIL
        socketserver.UDPServer.allow_reuse_address = True
        with socketserver.UDPServer((HOST, PORT), SyslogUDPHandler) as server:
            self.stdout.write(self.style.SUCCESS(
                f'Servidor UDP ouvindo em {HOST}:{PORT}'
            ))
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING('\nSaindo...'))
