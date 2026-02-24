import logging
import socketserver
import threading
import queue
import time
from django.core.management.base import BaseCommand
from log_receiver.parsers.fortinet import parse_fortinet_syslog
from vpn_logs.models import VPNFailure

logger = logging.getLogger(__name__)

# Fila thread-safe para escrita assincrona no banco
_device_queue = queue.Queue(maxsize=500)

# Throttle: re-registra cada device no máximo 1x por minuto
_device_last_seen: dict = {}
_device_throttle_lock = threading.Lock()
DEVICE_THROTTLE_SECONDS = 60

def _device_db_worker():
    """Worker de background que persiste os dispositivos detectados no banco.
    Roda em uma thread separada para nunca bloquear a recepção UDP."""
    from django import db
    while True:
        try:
            item = _device_queue.get(timeout=5)
            if item is None:  # Sinal de shutdown
                break
            devid, devname, ip = item
            db.connections.close_all()  # Garante conexão fresca
            from integrations.models import KnownDevice
            from django.utils import timezone
            try:
                KnownDevice.objects.update_or_create(
                    device_id=devid,
                    defaults={'hostname': devname, 'ip_address': ip, 'last_seen': timezone.now()}
                )
                logger.info(f"Device registered: {devid} ({ip})")
            except Exception as e:
                logger.warning(f"Device save failed for {devid}: {e}")
            finally:
                _device_queue.task_done()
        except queue.Empty:
            continue
        except Exception as e:
            logger.error(f"Device worker error: {e}")
            time.sleep(1)


# ─────────────────────────────────────────────────────────────────────────────
#  Funções auxiliares compartilhadas
# ─────────────────────────────────────────────────────────────────────────────

def parse_fortinet_timestamp(parsed_data):
    """
    Extrai o timestamp do log FortiGate usando a fonte mais precisa disponível:
    1. eventtime (nanoseconds epoch) com tz do log
    2. date + time + tz
    3. Agora (fallback)
    """
    from django.utils import timezone as dj_tz
    import datetime

    # 1ª opção: eventtime em nanosegundos
    eventtime_ns = parsed_data.get('eventtime', '')
    tz_str = parsed_data.get('tz', '-0300')  # FortiGate padrão Brasil
    try:
        if eventtime_ns and len(str(eventtime_ns)) > 15:
            ts_seconds = int(eventtime_ns) / 1e9
            dt = datetime.datetime.utcfromtimestamp(ts_seconds)
            # Aplica offset de tz
            sign = 1 if tz_str.startswith('+') else -1
            h = int(tz_str[1:3]) if len(tz_str) >= 3 else 0
            m = int(tz_str[3:5]) if len(tz_str) >= 5 else 0
            offset = datetime.timezone(sign * datetime.timedelta(hours=h, minutes=m))
            dt = dt.replace(tzinfo=datetime.timezone.utc).astimezone(offset)
            return dj_tz.make_aware(dt.replace(tzinfo=None), dj_tz.get_current_timezone())
    except Exception:
        pass

    # 2ª opção: date + time (local do FW)
    try:
        from dateutil.parser import parse as dateparse
        ts_str = f"{parsed_data.get('date', '')} {parsed_data.get('time', '')}"
        dt = dateparse(ts_str)
        if dj_tz.is_naive(dt):
            dt = dj_tz.make_aware(dt)  # Assume fuso do Django (America/Sao_Paulo)
        return dt
    except Exception:
        pass

    return dj_tz.now()


def map_severity(level_str):
    level = level_str.lower()
    if level in ('critical', 'alert', 'emergency'):
        return 'critical'
    elif level == 'error':
        return 'high'
    elif level in ('warning', 'warn'):
        return 'medium'
    elif level == 'notice':
        return 'low'
    return 'info'


# ─────────────────────────────────────────────────────────────────────────────
#  Handler UDP principal
# ─────────────────────────────────────────────────────────────────────────────

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytes.decode(self.request[0].strip(), 'utf-8', errors='ignore')
        client_address = self.client_address[0]

        try:
            # --- DETECÇÃO DE DISPOSITIVOS (sempre, mesmo com Syslog desativado) ---
            parsed_data = parse_fortinet_syslog(data)
            devid = parsed_data.get('devid', parsed_data.get('device_id', ''))
            self.record_device(devid, parsed_data, client_address)

            from integrations.models import SyslogConfig
            config = SyslogConfig.load()
            if not config.is_enabled:
                return

            # --- ROTEADOR DE PARSERS E MODELS ---
            log_type = parsed_data.get('type', '')
            subtype  = parsed_data.get('subtype', '')

            # 1. Eventos VPN
            if log_type == 'event' and subtype == 'vpn':
                action = parsed_data.get('action', '')
                if action in ['negotiate-error', 'auth-failure', 'ssl-login-fail', 'ipsec-login-fail']:
                    self.process_vpn_failure(parsed_data, client_address)
                elif action in ['tunnel-up', 'tunnel-down', 'ssl-new-session', 'ssl-exit']:
                    self.process_vpn_log(parsed_data, client_address)

            # 2. UTM (IPS, Antivírus, WebFilter, AppControl)
            elif log_type == 'utm':
                self.process_security_event(parsed_data, client_address)

            # 3. Traffic logs com UTM embutido (FortiOS envia assim às vezes)
            elif log_type == 'traffic' and parsed_data.get('utm-action', ''):
                self.process_security_event(parsed_data, client_address)

        except Exception as e:
            logger.error(f"Error parsing syslog from {client_address}: {e}", exc_info=True)

    # ─── Handlers específicos ───────────────────────────────────────────────

    def process_vpn_failure(self, parsed_data, source_emitter):
        from vpn_logs.models import VPNFailure

        username  = parsed_data.get('user', 'unknown')
        source_ip = parsed_data.get('remip', parsed_data.get('srcip', '0.0.0.0'))
        reason    = parsed_data.get('reason', parsed_data.get('action', ''))
        timestamp = parse_fortinet_timestamp(parsed_data)

        if not VPNFailure.objects.filter(
            user=username, source_ip=source_ip,
            timestamp=timestamp, reason=reason
        ).exists():
            VPNFailure.objects.create(
                user=username,
                source_ip=source_ip,
                timestamp=timestamp,
                reason=reason,
                country_code='',
                city='',
                raw_data=parsed_data
            )

    def process_vpn_log(self, parsed_data, source_emitter):
        from vpn_logs.models import VPNLog

        session_id = parsed_data.get('sessionid', parsed_data.get('tunnelid', ''))
        if not session_id:
            return

        username  = parsed_data.get('user', 'unknown')
        source_ip = parsed_data.get('remip', parsed_data.get('srcip', '0.0.0.0'))
        action    = parsed_data.get('action', '')
        timestamp = parse_fortinet_timestamp(parsed_data)

        if action in ['tunnel-up', 'ssl-new-session']:
            if not VPNLog.objects.filter(session_id=session_id).exists():
                VPNLog.objects.create(
                    session_id=session_id,
                    user=username,
                    source_ip=source_ip,
                    start_time=timestamp,
                    status=action,
                    raw_data=parsed_data
                )
        elif action in ['tunnel-down', 'ssl-exit']:
            vpn_log = VPNLog.objects.filter(session_id=session_id).first()
            if vpn_log:
                vpn_log.end_time = timestamp
                vpn_log.status   = action
                try:
                    vpn_log.bandwidth_out = int(parsed_data.get('sentbyte', 0))
                    vpn_log.bandwidth_in  = int(parsed_data.get('rcvdbyte', 0))
                    if vpn_log.start_time:
                        vpn_log.duration = int((timestamp - vpn_log.start_time).total_seconds())
                except Exception:
                    pass
                vpn_log.save()

    def process_security_event(self, parsed_data, source_emitter):
        """
        Roteia e salva eventos UTM do FortiGate preenchendo TODOS os campos
        específicos de cada subtype: IPS, Antivírus, WebFilter e AppControl.
        """
        from security_events.models import SecurityEvent
        import hashlib, json, urllib.parse

        # Mapeamento subtype FortiOS → choices do modelo
        SUBTYPE_MAP = {
            'webfilter':  'webfilter',
            'app-ctrl':   'app-control',
            'appctrl':    'app-control',
            'ips':        'ips',
            'virus':      'antivirus',
            'dlp':        'webfilter',  # DLP vai para webfilter por enquanto
        }

        fa_subtype  = parsed_data.get('subtype', parsed_data.get('utm-action', ''))
        mapped_type = SUBTYPE_MAP.get(fa_subtype)
        if not mapped_type:
            return

        # Deduplicação por hash do log completo
        log_str      = json.dumps(parsed_data, sort_keys=True)
        event_id_raw = hashlib.md5(log_str.encode()).hexdigest()
        if SecurityEvent.objects.filter(event_id=event_id_raw).exists():
            return

        src_ip    = parsed_data.get('srcip', '0.0.0.0')
        dst_ip    = parsed_data.get('dstip', '0.0.0.0')
        username  = parsed_data.get('user', '')
        action    = parsed_data.get('action', '')
        timestamp = parse_fortinet_timestamp(parsed_data)
        severity  = map_severity(parsed_data.get('level', ''))

        # ── Campos específicos por tipo ────────────────────────────────────
        extra = {}

        if mapped_type == 'ips':
            extra = {
                'attack_name': parsed_data.get('attack', parsed_data.get('attackname', '')),
                'attack_id':   parsed_data.get('attackid', ''),
                'cve':         parsed_data.get('cve', ''),
                'src_port':    _int(parsed_data.get('srcport')),
                'dst_port':    _int(parsed_data.get('dstport')),
                'src_country': urllib.parse.unquote(parsed_data.get('srccountry', '')),
            }

        elif mapped_type == 'antivirus':
            extra = {
                'virus_name': parsed_data.get('virus', parsed_data.get('virusid', '')),
                'file_name':  parsed_data.get('filename', parsed_data.get('fname', '')),
                'file_hash':  parsed_data.get('checksum', ''),
                'url':        urllib.parse.unquote(parsed_data.get('url', '')),
                'src_port':   _int(parsed_data.get('srcport')),
                'dst_port':   _int(parsed_data.get('dstport')),
            }

        elif mapped_type == 'webfilter':
            extra = {
                'url':        urllib.parse.unquote(parsed_data.get('url', '')),
                'category':   urllib.parse.unquote(parsed_data.get('catdesc', parsed_data.get('category', ''))),
                'src_port':   _int(parsed_data.get('srcport')),
                'dst_port':   _int(parsed_data.get('dstport')),
                'src_country': urllib.parse.unquote(parsed_data.get('srccountry', '')),
            }

        elif mapped_type == 'app-control':
            extra = {
                'app_name':     urllib.parse.unquote(parsed_data.get('app', parsed_data.get('appcat', ''))),
                'app_category': urllib.parse.unquote(parsed_data.get('appcat', '')),
                'app_risk':     parsed_data.get('apprisk', ''),
                'bytes_in':     _int(parsed_data.get('rcvdbyte')),
                'bytes_out':    _int(parsed_data.get('sentbyte')),
                'src_port':     _int(parsed_data.get('srcport')),
                'dst_port':     _int(parsed_data.get('dstport')),
            }

        try:
            SecurityEvent.objects.create(
                event_id=event_id_raw,
                event_type=mapped_type,
                severity=severity,
                timestamp=timestamp,
                date=timestamp.date(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                username=username,
                action=action,
                raw_log=log_str,
                **extra
            )
            logger.info(f"SecurityEvent saved: {mapped_type} from {source_emitter}")
        except Exception as e:
            logger.error(f"Erro ao salvar SecurityEvent ({mapped_type}): {e}")

    def record_device(self, devid, parsed_data, ip):
        if not devid:
            devid = f"UNKNOWN-{ip}"
        devname = parsed_data.get('devname', f"Device at {ip}")

        # Throttle: enfileira no máximo 1x por DEVICE_THROTTLE_SECONDS por device
        with _device_throttle_lock:
            last = _device_last_seen.get(devid, 0)
            now  = time.time()
            if now - last < DEVICE_THROTTLE_SECONDS:
                return  # Mesmo device, passagem rápida — ignora
            _device_last_seen[devid] = now

        try:
            _device_queue.put_nowait((devid, devname, ip))
        except queue.Full:
            logger.warning("Device queue is full, skipping registration")


# ─────────────────────────────────────────────────────────────────────────────
#  Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _int(value, default=None):
    """Converte para int com fallback seguro."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


# ─────────────────────────────────────────────────────────────────────────────
#  Management Command
# ─────────────────────────────────────────────────────────────────────────────

class Command(BaseCommand):
    help = 'Starts the UDP Syslog Receiver Daemon on port 5140'

    def handle(self, *args, **options):
        HOST, PORT = "0.0.0.0", 5140
        self.stdout.write(self.style.SUCCESS(
            f'Iniciando Syslog Receiver Passivo em {HOST}:{PORT}/UDP...'
        ))
        print(f"LOG: Syslog Receiver started on {HOST}:{PORT}", flush=True)

        # Inicia o worker de escrita assíncrona de dispositivos
        worker = threading.Thread(target=_device_db_worker, daemon=True)
        worker.start()

        with socketserver.ThreadingUDPServer((HOST, PORT), SyslogUDPHandler) as server:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING('\nSaindo do Syslog Receiver...'))
