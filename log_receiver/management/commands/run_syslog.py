import logging
import socketserver
import threading
from django.core.management.base import BaseCommand
from log_receiver.parsers.fortinet import parse_fortinet_syslog
from vpn_logs.models import VPNFailure

logger = logging.getLogger(__name__)

class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = bytes.decode(self.request[0].strip(), 'utf-8', errors='ignore')
        socket = self.request[1]
        client_address = self.client_address[0]
        
        print(f"--- SYSLOG RECEIVED FROM {client_address} ---", flush=True)
        print(data[:200], flush=True) # Primeiros 200 caracteres
        
        try:
            # --- DETECÇÃO DE DISPOSITIVOS (sempre, mesmo com Syslog desativado) ---
            parsed_data = parse_fortinet_syslog(data)
            devid = parsed_data.get('devid', parsed_data.get('device_id', ''))
            self.record_device(devid, parsed_data, client_address)

            from integrations.models import SyslogConfig
            config = SyslogConfig.load()
            if not config.is_enabled:
                # Se desativado, registrou o device mas para o processamento de log
                return

            # --- ROTEADOR DE PARSERS E MODELS ---
            log_type = parsed_data.get('type', '')
            subtype = parsed_data.get('subtype', '')

            # 1. Evento de VPN (Possivel Brute Force ou Acesso)
            if log_type == 'event' and subtype == 'vpn':
                action = parsed_data.get('action', '')
                if action in ['negotiate-error', 'auth-failure', 'ssl-login-fail', 'ipsec-login-fail']:
                    self.process_vpn_failure(parsed_data, client_address)
                elif action in ['tunnel-up', 'tunnel-down', 'ssl-new-session', 'ssl-exit']:
                    self.process_vpn_log(parsed_data, client_address)

            # 2. Eventos de Segurança (Web, IPS, UTM, AppControl)
            elif log_type == 'utm':
                self.process_security_event(parsed_data, client_address)

        except Exception as e:
            logger.error(f"Error parsing syslog from {client_address}: {e}")

    def process_vpn_failure(self, parsed_data, source_emitter):
        from vpn_logs.models import VPNFailure
        from django.utils import timezone
        import urllib.parse
        from dateutil.parser import parse
        import hashlib
        
        username = parsed_data.get('user', 'unknown')
        source_ip = parsed_data.get('remip', parsed_data.get('srcip', '0.0.0.0'))
        
        try:
            ts_str = f"{parsed_data.get('date', '')} {parsed_data.get('time', '')}"
            timestamp = parse(ts_str)
            if timezone.is_naive(timestamp):
                timestamp = timezone.make_aware(timestamp)
            # Offset time just like FA if needed
        except:
            timestamp = timezone.now()

        reason = parsed_data.get('reason', parsed_data.get('action', ''))
        fa_country = urllib.parse.unquote(parsed_data.get('srccountry', parsed_data.get('remcountry', '')))
        
        # Deduplication (Event Hash for UDP Stream)
        log_signature = f"{username}_{source_ip}_{timestamp.isoformat()}_{reason}"
        event_hash = hashlib.md5(log_signature.encode('utf-8')).hexdigest()
        
        if not VPNFailure.objects.filter(user=username, source_ip=source_ip, timestamp=timestamp, reason=reason).exists():
            VPNFailure.objects.create(
                user=username,
                source_ip=source_ip,
                timestamp=timestamp,
                reason=reason,
                country_code='',
                city='',
                raw_data=parsed_data
            )
            # logger.info(f"Salvo BruteForce Passivo: {username} from {source_ip}")

    def process_security_event(self, parsed_data, source_emitter):
        from security_events.models import SecurityEvent
        from django.utils import timezone
        import urllib.parse
        from dateutil.parser import parse
        import hashlib
        import json

        event_type_map = {
            'webfilter': 'webfilter',
            'app-ctrl': 'appcontrol',
            'ips': 'ips',
            'virus': 'antivirus'
        }
        
        fa_subtype = parsed_data.get('subtype', '')
        mapped_type = event_type_map.get(fa_subtype)
        
        if not mapped_type:
            return

        username = parsed_data.get('user', '')
        src_ip = parsed_data.get('srcip', '0.0.0.0')
        dst_ip = parsed_data.get('dstip', '0.0.0.0')
        
        log_str = json.dumps(parsed_data, sort_keys=True)
        event_id_raw = hashlib.md5(log_str.encode('utf-8')).hexdigest()

        if SecurityEvent.objects.filter(event_id=event_id_raw).exists():
            return
            
        try:
            ts_str = f"{parsed_data.get('date', '')} {parsed_data.get('time', '')}"
            timestamp = parse(ts_str)
            if timezone.is_naive(timestamp):
                timestamp = timezone.make_aware(timestamp)
        except:
            timestamp = timezone.now()

        severity = 'info'
        fa_level = parsed_data.get('level', '').lower()
        if fa_level in ['critical', 'alert', 'emergency']: severity = 'critical'
        elif fa_level == 'error': severity = 'high'
        elif fa_level == 'warning': severity = 'medium'
        elif fa_level == 'notice': severity = 'low'
        
        action = parsed_data.get('action', '')
        # Map common actions if needed
        is_blocked = True if 'block' in action.lower() or 'drop' in action.lower() else False

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
                raw_log=log_str
            )
            # logger.info(f"Salvo UTM Passivo: {mapped_type} - {username} de {src_ip}")
        except Exception as e:
            logger.error(f"Erro ao salvar syslog secevent: {e}")

    def record_device(self, devid, parsed_data, ip):
        from integrations.models import KnownDevice
        from django.utils import timezone
        from django import db
        
        if not devid:
            devid = f"UNKNOWN-{ip}"
        
        devname = parsed_data.get('devname', f"Device at {ip}")
        
        # Fecha conexões antigas para garantir reconexão limpa (crítico para MSSQL)
        db.connections.close_all()
        
        try:
            KnownDevice.objects.update_or_create(
                device_id=devid,
                defaults={
                    'hostname': devname,
                    'ip_address': ip,
                    'last_seen': timezone.now()
                }
            )
        except Exception as e:
            # Log o erro mas não deixa o receiver cair
            logger.warning(f"Could not register device {devid} ({ip}): {e}")
            # Segunda tentativa após reset
            try:
                db.connections.close_all()
                KnownDevice.objects.update_or_create(
                    device_id=devid,
                    defaults={
                        'hostname': devname,
                        'ip_address': ip,
                        'last_seen': timezone.now()
                    }
                )
            except Exception as e2:
                logger.error(f"Device registration failed permanently for {devid}: {e2}")

    def process_vpn_log(self, parsed_data, source_emitter):
        from vpn_logs.models import VPNLog
        from django.utils import timezone
        from dateutil.parser import parse
        import json

        session_id = parsed_data.get('sessionid', parsed_data.get('tunnelid', ''))
        if not session_id:
            return

        username = parsed_data.get('user', 'unknown')
        source_ip = parsed_data.get('remip', parsed_data.get('srcip', '0.0.0.0'))
        action = parsed_data.get('action', '')
        
        try:
            ts_str = f"{parsed_data.get('date', '')} {parsed_data.get('time', '')}"
            timestamp = parse(ts_str)
            if timezone.is_naive(timestamp):
                timestamp = timezone.make_aware(timestamp)
        except:
            timestamp = timezone.now()

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
                vpn_log.status = action
                # Atualizar banda se disponível
                try:
                    sent = int(parsed_data.get('sentbyte', 0))
                    rcvd = int(parsed_data.get('rcvdbyte', 0))
                    vpn_log.bandwidth_out = sent
                    vpn_log.bandwidth_in = rcvd
                    if vpn_log.start_time:
                        duration = (timestamp - vpn_log.start_time).total_seconds()
                        vpn_log.duration = int(duration)
                except:
                    pass
                vpn_log.save()


class Command(BaseCommand):
    help = 'Starts the UDP Syslog Receiver Daemon on port 5140'

    def handle(self, *args, **options):
        HOST, PORT = "0.0.0.0", 5140
        self.stdout.write(self.style.SUCCESS(f'Iniciando Syslog Receiver Passivo em {HOST}:{PORT}/UDP...'))
        print(f"LOG: Syslog Receiver started on {HOST}:{PORT}", flush=True)
        
        # ThreadingUDPServer prevents blocking on multiple incoming logs
        with socketserver.ThreadingUDPServer((HOST, PORT), SyslogUDPHandler) as server:
            try:
                server.serve_forever()
            except KeyboardInterrupt:
                self.stdout.write(self.style.WARNING('\nSaindo do Syslog Receiver...'))
