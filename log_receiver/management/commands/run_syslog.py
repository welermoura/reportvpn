import sys
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

# Fila principal: raw (ip, data_str) — Aumentada para 200k
_raw_queue = queue.Queue(maxsize=200000)

# Fila de dispositivos (baixo volume pós-throttle)
_device_queue = queue.Queue(maxsize=2000)

# Throttle: 1 update/min por device_id
_device_last_seen: dict = {}
_device_throttle_lock = threading.Lock()
DEVICE_THROTTLE_SECONDS = 60

# Número de workers de processamento (Aumentado para 16)
NUM_WORKERS = 16

# Tamanho do batch para bulk_create de SecurityEvents
BATCH_SIZE = 100
BATCH_FLUSH_INTERVAL = 1.0  # Flush mais agressivo


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
            # SÓ fecha se o banco reclamar ou periodicamente (menos agressivo que close_all literal)
            # db.connections.close_all() 
            
            # MSSQL não suporta ignore_conflicts — deduplica via query prévia
            ids_no_batch = [obj.event_id for obj in batch_buffer]
            ja_existentes = set(
                SecurityEvent.objects.filter(event_id__in=ids_no_batch)
                .values_list('event_id', flat=True)
            )
            novos = [obj for obj in batch_buffer if obj.event_id not in ja_existentes]
            if novos:
                SecurityEvent.objects.bulk_create(novos)
                # logger.debug(f"[W{worker_id}] bulk_create: {len(novos)}")
        except Exception as e:
            logger.error(f"[W{worker_id}] bulk_create failed: {e}")
            db.connections.close_all() # Fecha aqui se deu erro
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
            try:
                item = _raw_queue.get(timeout=BATCH_FLUSH_INTERVAL)
                logger.debug(f"[RECEPTOR] Item recebido de {item[0]}")
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

                # --- System & SD-WAN Alerts ---
                elif log_type == 'event' or log_type == 'sdwan' or subtype == 'sdwan':
                    _process_system_alert(parsed, ip)

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


def _process_system_alert(parsed_data, source_ip):
    """Detecta alertas críticos de sistema (CPU, Memória, Link) e atualiza o KnownDevice."""
    devid = parsed_data.get('devid')
    
    # LOG VERBOSO PARA DIAGNÓSTICO
    raw_str = " ".join([f"{k}={v}" for k,v in parsed_data.items()])
    logger.error(f"DEBUG_SYS: ip={source_ip} devid={devid} data={raw_str[:300]}")

    # Captura todo o conteúdo do log para busca genérica (msg, logdesc, reason, status)
    raw_content = " ".join([str(v) for v in parsed_data.values()]).lower()
    
    update_fields = {}
    alert = None

    # Detecção de CPU/Memória
    if 'cpu' in raw_content and ('limit' in raw_content or 'high' in raw_content or 'exhaustion' in raw_content):
        alert = f"CPU Alta: {parsed_data.get('msg', 'Carga de CPU detectada')}"
        update_fields['cpu_status'] = 'alto'
    elif ('mem' in raw_content or 'ram' in raw_content) and ('limit' in raw_content or 'high' in raw_content or 'exhaustion' in raw_content):
        alert = f"Memória Alta: {parsed_data.get('msg', 'Carga de Memória detectada')}"
        update_fields['memory_status'] = 'alto'
    elif 'conserve' in raw_content:
        alert = f"Conserve Mode: {parsed_data.get('msg', 'Entrou em Conserve Mode')}"
        update_fields['conserve_mode'] = True
        update_fields['memory_status'] = 'alto'
    
    # Detecção de Link/SD-WAN (Restrito a Health Checks reais)
    # Buscamos o contexto nos campos principais e EXCLUÍMOS portas de switch e eventos de usuário
    msg_and_desc = (parsed_data.get('msg', '') + " " + parsed_data.get('logdesc', '')).lower()
    
    # Contexto de saúde: SD-WAN, SLA ou Health-Check
    # Exigimos termos específicos de monitoramento de link
    is_health_context = any(x in msg_and_desc for x in ['health-check', 'sla', 'link-monitor', 'connection lost']) or \
                        (parsed_data.get('subtype') == 'sdwan' and 'health-check' in msg_and_desc)
    
    # Exclusão explícita de interfaces de switch e eventos de autenticação/usuário
    is_excluded = any(x in msg_and_desc for x in ['switch port', 'fortiswitch', 'switch-port', 'auth logon', 'user '])
    
    # Peça chave: se o log tem status=up ou success, ignoramos qualquer palavra de falha na mensagem
    status_val = (parsed_data.get('status') or parsed_data.get('state') or '').lower()
    is_up_msg = any(x in raw_content for x in [' up', 'up ', 'recovered', 'success', 'passed']) or status_val in ['up', 'success', 'passed']
    
    # Keywords de falha (latência só conta se não for um log de UP)
    is_failure = any(x in raw_content for x in ['down', 'dead', 'fail', 'alarm'])
    if 'latency' in raw_content and not is_up_msg:
        is_failure = True
    
    # Decisão final de estado
    is_recovery = is_up_msg and not is_failure
    
    if is_health_context and (is_failure or is_recovery) and not is_excluded:
        logger.info(f"ALERTA DETECTADO (LINK NOVO): context={is_health_context} fail={is_failure} recov={is_recovery} status={status_val}")
        
        # Tenta pegar a interface (campo comum em logs de rede)
        interface = parsed_data.get('interface') or parsed_data.get('intf') or parsed_data.get('member')
        
        # Se não achou em campo dedicado, tenta extrair da mensagem (ex: "Link Monitor: wan2 status is down")
        msg_val = parsed_data.get('msg', '')
        if not interface and msg_val:
            import re
            # Procura por padrões complexos de interface (ex: "ADSL-WJ;600 (internal3)" ou "wan2")
            # Tenta pegar o que está antes do parêntese ou o nome simples
            intf_match = re.search(r'(interface|intf|monitor):\s*([^,;]+(?:;[^,;\s]+)?)', msg_val, re.I)
            if intf_match:
                interface = intf_match.group(2).strip()
            else:
                # Tenta pegar qualquer palavra que siga padrões comuns de interface se não achou com o prefixo
                intf_match = re.search(r'\s([a-zA-Z0-9_\-]+(?:;[a-zA-Z0-9_\-]+)?)\s+(?:status|is|may)', msg_val, re.I)
                if intf_match:
                    interface = intf_match.group(1).strip()

        if is_failure:
            update_fields['link_status'] = 'alarme'
            prefix = "Link Down"
        else:
            update_fields['link_status'] = 'normal'
            prefix = "Link UP"

        # Tenta pegar a mensagem mais descritiva possível
        desc = parsed_data.get('msg') or parsed_data.get('logdesc') or "Mudança de estado no link"
        
        # Se temos o nome da interface mas ele NÃO está no texto da mensagem, vamos adicioná-lo
        if interface:
            interface_clean = str(interface).strip()
            if interface_clean.lower() not in desc.lower():
                alert = f"{prefix} ({interface_clean}): {desc}"
            else:
                alert = f"{prefix}: {desc}"
        else:
            alert = f"{prefix}: {desc}"

    if alert or update_fields:
        from integrations.models import KnownDevice
        from django.utils import timezone
        
        if alert:
            update_fields['last_alert_message'] = alert
            update_fields['last_alert_time'] = timezone.now()

        # Estratégia de busca robusta:
        # 1. Tenta por Serial (devid)
        # 2. Tenta por IP de origem
        device = None
        find_method = "None"
        if devid:
            device = KnownDevice.objects.filter(device_id=devid).first()
            if device:
                find_method = "Serial (devid)"
        
        if not device and source_ip:
            device = KnownDevice.objects.filter(ip_address=source_ip).first()
            if device:
                find_method = "IP Address"
            
        if device:
            # Se achou pelo IP mas devid é diferente, talvez o dispositivo tenha novo serial ou o log seja ambíguo
            logger.error(f"DEBUG: Atribuindo alerta para {device.hostname} ({device.device_id}) via {find_method}. Org_DevID={devid}, Org_IP={source_ip}")
            KnownDevice.objects.filter(pk=device.pk).update(**update_fields)
        else:
            logger.error(f"DEBUG: Dispositivo não encontrado para devid={devid} ip={source_ip}")


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

        # 1. Inicia worker de dispositivos (1 thread)
        threading.Thread(target=_device_db_worker, daemon=True, name="device-worker").start()

        # 2. Inicia pool de workers de log
        for i in range(NUM_WORKERS):
            threading.Thread(
                target=_log_processor_worker,
                args=(i,),
                daemon=True,
                name=f"log-worker-{i}"
            ).start()

        # 3. Monitor de saúde (imprime stats a cada 60s)
        def _monitor():
            while True:
                time.sleep(60)
                logger.info(
                    f"[MONITOR] raw_q={_raw_queue.qsize()} dev_q={_device_queue.qsize()} known={len(_device_last_seen)}"
                )
        threading.Thread(target=_monitor, daemon=True, name="monitor").start()

        # 4. Servidor UDP
        socketserver.UDPServer.allow_reuse_address = True
        with socketserver.UDPServer((HOST, PORT), SyslogUDPHandler) as server:
            self.stdout.write(self.style.SUCCESS(f'Servidor UDP ouvindo em {HOST}:{PORT}'))
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING('\nSaindo...'))
