import sys
import logging
import socketserver
import threading
import queue
import time

from django.core.management.base import BaseCommand
from log_receiver.parsers.fortinet import parse_fortinet_syslog

import redis
from integrations.ad import ActiveDirectoryClient
 
logger = logging.getLogger(__name__)

# Conexão direta com Redis para deduplicação ultra-rápida
try:
    redis_client = redis.Redis(host='redis', port=6379, db=2, decode_responses=True)
except:
    redis_client = None

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
    """Processa o raw_queue em batches e salva SecurityEvents."""
    from django import db
    from security_events.models import SecurityEvent
    ad_client = ActiveDirectoryClient()
    
    batch_buffer = []
    last_flush = time.time()

    def flush_batch():
        nonlocal batch_buffer, last_flush
        if not batch_buffer:
            return
        try:
            # Estratégia DEFINITIVA: 
            # 1. Filtramos o que já está no Redis (seen_ids)
            # 2. O que sobrou, tentamos gravar no Banco.
            
            novos_reais = []
            if redis_client:
                # Batch check no Redis (MGET)
                ids = [obj.event_id for obj in batch_buffer]
                seen_values = redis_client.mget([f"se:{i}" for i in ids])
                
                pipeline = redis_client.pipeline()
                for obj, seen in zip(batch_buffer, seen_values):
                    if not seen:
                        novos_reais.append(obj)
                        # Marca como visto por 10 min
                        pipeline.setex(f"se:{obj.event_id}", 600, "1")
                pipeline.execute()
            else:
                novos_reais = batch_buffer

            if novos_reais:
                # Como usamos Redis, confiamos que são novos (reduz carga de query no SQL)
                SecurityEvent.objects.bulk_create(novos_reais)
                # logger.info(f"[W{worker_id}] Gravados: {len(novos_reais)}")
                
        except Exception as e:
            logger.error(f"[W{worker_id}] bulk_create failed: {e}")
            db.connections.close_all()
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
                elif log_type in ['utm', 'ips', 'virus', 'webfilter', 'app-ctrl'] or (log_type == 'traffic' and parsed.get('utm-action')):
                    se = _build_security_event(parsed, raw_data, ad_client)
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


def get_geoip_data(ip):
    """
    Busca país e cidade de um IP público usando ip-api.com com cache no Redis (24h).
    """
    if not ip or ip.startswith(('10.', '172.16.', '192.168.', '127.', '0.0.0.0')):
        return {}

    cache_key = f"geoip:{ip}"
    if redis_client:
        cached = redis_client.get(cache_key)
        if cached:
            import json
            try:
                return json.loads(cached)
            except:
                pass

    try:
        import requests, json
        # Usando ip-api (gratuito para demo)
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()
        if data.get('status') == 'success':
            res = {
                'country': data.get('country'),
                'city': data.get('city'),
                'country_code': data.get('countryCode')
            }
            if redis_client:
                redis_client.setex(cache_key, 86400, json.dumps(res)) # 24h cache
            return res
    except Exception as e:
        logger.error(f"GeoIP Error for {ip}: {e}")
    
    return {}


def _build_security_event(parsed_data, raw_data, ad_client=None):
    """Constrói (sem salvar) um objeto SecurityEvent rico com todos os campos."""
    import hashlib, json, urllib.parse
    from security_events.models import SecurityEvent

    SUBTYPE_MAP = {
        'webfilter': 'webfilter', 'app-ctrl': 'app-control',
        'appctrl': 'app-control', 'ips': 'ips',
        'virus': 'antivirus', 'dlp': 'webfilter',
    }
    fa_subtype  = parsed_data.get('subtype', '')
    fa_type     = parsed_data.get('type', '')
    
    # Mapeamento prioritário por subtipo, fallback para o tipo principal
    mapped_type = SUBTYPE_MAP.get(fa_subtype)
    if not mapped_type:
        if fa_type == 'ips': mapped_type = 'ips'
        elif fa_type == 'virus': mapped_type = 'antivirus'

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

    # 4. Enriquecimento AD
    if username and ad_client:
        ad_info = ad_client.get_user_info(username)
        if ad_info:
            kwargs.update(
                user_email=ad_info.get('email', ''),
                user_department=ad_info.get('department', ''),
                ad_title=ad_info.get('title', ''),
                ad_display_name=ad_info.get('display_name', ''),
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
        # Limpeza de sessões "zombie" (se o usuário já estava logado e o tunnel-down foi perdido)
        VPNLog.objects.filter(
            user=username, 
            status__in=['active', 'tunnel-up']
        ).exclude(session_id=session_id).update(
            status='closed', 
            end_time=ts
        )

        if not VPNLog.objects.filter(session_id=session_id).exists():
            # Enriquecimento AD
            ad_info = {}
            if username and username not in ['unknown', 'N/A']:
                try:
                    from integrations.ad import ActiveDirectoryClient
                    ad_client = ActiveDirectoryClient()
                    clean_user = username.split('\\')[-1]
                    ad_info = ad_client.get_user_info(clean_user) or {}
                except Exception as e:
                    logger.error(f"Erro ao enriquecer VPNLog com AD: {e}")

            # Enriquecimento GeoIP (Nativo do FortiGate ou Mapeamento)
            import urllib.parse
            rem_country = urllib.parse.unquote(str(parsed_data.get('remcountry', '') or parsed_data.get('srccountry', '')).strip())
            rem_city = urllib.parse.unquote(str(parsed_data.get('remcity', '') or parsed_data.get('srccity', '')).strip())
            
            # Limpeza de campos vazios/reservados
            country_name = rem_country if rem_country.lower() not in ['reserved', 'n/a'] else ''
            city = rem_city if rem_city.lower() not in ['reserved', 'n/a'] else ''
            
            # Fallback Automático: Se o firewall não mandou a localização, nós descobrimos via API
            if not country_name and source_ip:
                gdata = get_geoip_data(source_ip)
                if gdata:
                    country_name = gdata.get('country', '')
                    city = gdata.get('city', '')
                    country_code = gdata.get('country_code', '')
            
            # Mapeamento de código de país básico (se ainda não tiver do gdata)
            if not locals().get('country_code'):
                COUNTRY_MAP = {
                    'brazil': 'BR', 'united states': 'US', 'argentina': 'AR', 
                    'mexico': 'MX', 'chile': 'CL', 'colombia': 'CO', 'peru': 'PE',
                    'paraguay': 'PY', 'uruguay': 'UY', 'canada': 'CA', 'germany': 'DE',
                    'france': 'FR', 'united kingdom': 'GB', 'spain': 'ES', 'portugal': 'PT'
                }
                country_code = COUNTRY_MAP.get(country_name.lower(), '')

            # Detecção de suspeito
            is_suspicious = False
            try:
                from integrations.models import FortiAnalyzerConfig
                fa_config = FortiAnalyzerConfig.load()
                trusted = [c.strip().upper() for c in fa_config.trusted_countries.split(',')]
                if country_code and country_code.upper() not in trusted:
                    is_suspicious = True
            except Exception:
                pass

            # Usamos get_or_create para garantir que não criamos duplicatas por race condition
            # com a tarefa de polling (tasks.py)
            VPNLog.objects.get_or_create(
                session_id=session_id,
                defaults={
                    'user': username,
                    'source_ip': source_ip,
                    'start_time': ts,
                    'status': action,
                    'raw_data': parsed_data,
                    'ad_department': ad_info.get('department'),
                    'ad_email': ad_info.get('email'),
                    'ad_title': ad_info.get('title'),
                    'ad_display_name': ad_info.get('display_name'),
                    'country_name': country_name,
                    'country_code': country_code,
                    'city': city,
                    'is_suspicious': is_suspicious,
                    'last_activity': ts
                }
            )
        else:
            # Sessão já existe, apenas garantir que last_activity está preenchido
            if not VPNLog.objects.filter(session_id=session_id, last_activity__isnull=False).exists():
                VPNLog.objects.filter(session_id=session_id).update(last_activity=ts)

    elif action == 'tunnel-stats':
        # Heartbeat: Atualiza o sinal de vida da sessão
        # Não usamos get_or_create aqui para não criar sessões sem tunnel-up via syslog
        # (A sincronização via API tasks.py cuidará de criar se faltar)
        VPNLog.objects.filter(session_id=session_id, status__in=['active', 'tunnel-up']).update(last_activity=ts)

    elif action in ['tunnel-down', 'ssl-exit']:
        vpn_log = VPNLog.objects.filter(session_id=session_id).first()
        if vpn_log:
            vpn_log.end_time      = ts
            vpn_log.status        = action
            vpn_log.bandwidth_out = _int(parsed_data.get('sentbyte'), 0)
            vpn_log.bandwidth_in  = _int(parsed_data.get('rcvdbyte'), 0)
            
            # Prioriza a duração enviada pelo Fortigate
            forti_duration = _int(parsed_data.get('duration'))
            if forti_duration is not None:
                vpn_log.duration = forti_duration
            elif vpn_log.start_time:
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
        interface = parsed_data.get('interface') or parsed_data.get('intf') or \
                    parsed_data.get('member') or parsed_data.get('devname_vdom')
        
        # Tenta pegar o nome do SLA/Health-Check como Alias
        sla_name = parsed_data.get('health-check-name') or parsed_data.get('sla-name') or \
                   parsed_data.get('service-name') or parsed_data.get('vlan')

        # Se não achou em campo dedicado, tenta extrair da mensagem
        msg_val = parsed_data.get('msg', '')
        if not interface and msg_val:
            import re
            intf_match = re.search(r'(?:interface|intf|monitor|member|port):\s*([^,"]+)', msg_val, re.I)
            if intf_match:
                interface = intf_match.group(1).strip()
            else:
                intf_match = re.search(r'\s([a-zA-Z0-9_\-\.\s\(\);]+?)\s+(?:status|is|may|changed)', msg_val, re.I)
                if intf_match:
                    interface = intf_match.group(1).strip()

        if is_failure:
            update_fields['link_status'] = 'alarme'
            prefix = "Link Down"
        else:
            update_fields['link_status'] = 'normal'
            prefix = "Link UP"

        desc = parsed_data.get('msg') or parsed_data.get('logdesc') or "Mudança de estado no link"
        
        # Formata o alerta final privilegiando o SLA Name se disponível
        if sla_name and interface and str(sla_name).lower() != str(interface).lower():
            alert = f"{prefix} {sla_name} ({interface}): {desc}"
        elif interface:
            alert = f"{prefix} ({interface}): {desc}"
        elif sla_name:
            alert = f"{prefix} ({sla_name}): {desc}"
        else:
            alert = f"{prefix}: {desc}"

    if alert or update_fields:
        from integrations.models import KnownDevice
        from django.utils import timezone
        
        if alert:
            update_fields['last_alert_message'] = alert
            update_fields['last_alert_time'] = timezone.now()

        # Estratégia de busca e Throttling (evitar UPDATE no banco a cada segundo)
        device = None
        if devid:
            device = KnownDevice.objects.filter(device_id=devid).first()
        if not device and source_ip:
            device = KnownDevice.objects.filter(ip_address=source_ip).first()
            
        if device:
            # SÓ atualiza se o status mudou ou se passou o tempo de throttle (5 min para info básica)
            status_changed = (update_fields.get('link_status') and update_fields['link_status'] != device.link_status)
            needs_update = status_changed or alert
            
            if needs_update:
                KnownDevice.objects.filter(pk=device.pk).update(**update_fields)
                logger.info(f"STATUS CHANGE: Device {device.hostname} updated. Reason: {'Alert' if alert else 'Link Change'}")


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
        # DESCARTE INTELIGENTE: se a fila estiver > 90%, descartar logs de tráfego simples
        qsize = _raw_queue.qsize()
        if qsize > 180000: # 90% da fila
             # Se for apenas tráfego sem segurança, descarta
             if 'type=traffic' in data and 'utm-action' not in data:
                 return

        try:
            _raw_queue.put_nowait((ip, data))
        except queue.Full:
            # Emergência: se nem com o descarte liberou, logamos o erro
             pass


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
