from celery import shared_task
from django.utils import timezone
from django.core.cache import cache
from django.db import IntegrityError
from dateutil.parser import parse
from integrations.fortianalyzer import FortiAnalyzerClient
from integrations.ad import ActiveDirectoryClient
from integrations.geoip import GeoIPClient
from .models import SecurityEvent
import datetime
import logging
import json
import urllib.parse
import hashlib

logger = logging.getLogger(__name__)

LOCK_EXPIRE = 60 * 10  # Lock expires in 10 minutes

@shared_task(bind=True, name='Coleta de Eventos de Segurança (Geral)')
def fetch_security_events_task(self, target_subtype=None):
    """
    Task para coletar eventos de segurança (IPS, Antivirus, WebFilter) do FortiAnalyzer.
    Pode ser executada para todos ou apenas um subtipo específico via 'target_subtype'.
    """
    lock_id = f"fetch_security_events_lock_{target_subtype or 'all'}"
    acquire_lock = lambda: cache.add(lock_id, "true", LOCK_EXPIRE)
    release_lock = lambda: cache.delete(lock_id)

    if not acquire_lock():
        logger.warning(f"Task fetch_security_events_task ({target_subtype or 'all'}) is already running.")
        return "Locked"

    try:
        logger.info(f"Starting fetch_security_events_task (target={target_subtype or 'all'})...")
        
        fa_client = FortiAnalyzerClient()
        ad_client = ActiveDirectoryClient()
        geoip_client = GeoIPClient()

        # Configurações de busca
        days_ago = 7
        start_date = timezone.now() - datetime.timedelta(days=days_ago)
        fetch_limit = 1000
        
        # Subtipos para coletar
        all_subtypes = [
            {'name': 'ips', 'log_type': 'ips', 'filter': 'subtype=="ips"'},
            {'name': 'antivirus', 'log_type': 'virus', 'filter': 'subtype=="virus"'},
            {'name': 'webfilter', 'log_type': 'webfilter', 'filter': 'subtype=="webfilter"'}
        ]
        
        if target_subtype:
            subtypes = [s for s in all_subtypes if s['name'] == target_subtype]
            if not subtypes:
                return f"Invalid target_subtype: {target_subtype}"
        else:
            subtypes = all_subtypes
            
        summary = {}

        for subtype in subtypes:
            logger.info(f"Iniciando coleta para subtype: {subtype['name']} (logtype: {subtype['log_type']})")
            
            tid = fa_client.start_log_task(
                log_type=subtype['log_type'],
                start_time=start_date, 
                limit=fetch_limit, 
                log_filter=subtype['filter']
            )
            
            if not tid:
                logger.error(f"Falha ao obter TID do FA para {subtype['name']}.")
                summary[subtype['name']] = "Failed to start task"
                continue
                
            # Aguardar processamento do FA (polling simplificado conforme vpn_logs)
            import time
            time.sleep(10)
            
            response = fa_client.get_task_results(tid, limit=fetch_limit)
            
            if not response:
                logger.warning(f"Nenhum dado retornado do FA para {subtype['name']}.")
                summary[subtype['name']] = "No data"
                continue

            logs_data = []
            if 'result' in response:
                res = response['result']
                if isinstance(res, dict):
                    logs_data = res.get('data', [])
                elif isinstance(res, list) and len(res) > 0:
                    logs_data = res[0].get('data', [])
            
            logger.info(f"Processando {len(logs_data)} registros para {subtype['name']}.")
            
            count_new = 0
            for log in logs_data:
                # Gerar um ID único robusto usando hash do log inteiro
                # Isso evita colisões quando múltiplos eventos ocorrem no mesmo segundo
                log_str = json.dumps(log, sort_keys=True)
                event_id_raw = hashlib.md5(log_str.encode('utf-8')).hexdigest()
                
                if SecurityEvent.objects.filter(event_id=event_id_raw).exists():
                    continue

                # Mapeamento básico de campos
                username = log.get('user', '')
                src_ip = log.get('srcip', '0.0.0.0')
                dst_ip = log.get('dstip', '0.0.0.0')
                
                try:
                    ts_str = f"{log.get('date', '')} {log.get('time', '')}"
                    timestamp = parse(ts_str)
                    if timezone.is_naive(timestamp):
                        timestamp = timezone.make_aware(timestamp)
                    
                    # Fix: Adjust for FA being 1 hour ahead
                    timestamp = timestamp - datetime.timedelta(hours=1)
                except:
                    timestamp = timezone.now()

                # Severidade (Mapear de level do FA se existir)
                fa_level = log.get('level', '').lower()
                severity = 'info'
                if fa_level in ['critical', 'alert', 'emergency']:
                    severity = 'critical'
                elif fa_level == 'error':
                    severity = 'high'
                elif fa_level == 'warning':
                    severity = 'medium'
                elif fa_level == 'notice':
                    severity = 'low'

                # Criar instância básica
                event = SecurityEvent(
                    event_id=event_id_raw,
                    event_type=subtype['name'],
                    severity=severity,
                    timestamp=timestamp,
                    date=timestamp.date(),
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=int(log.get('srcport', 0)) if log.get('srcport') else None,
                    dst_port=int(log.get('dstport', 0)) if log.get('dstport') else None,
                    username=username,
                    raw_log=json.dumps(log)
                )

                # Enriquecimento AD
                if username:
                    ad_info = ad_client.get_user_info(username)
                    if ad_info:
                        event.user_email = ad_info.get('email', '')
                        event.user_department = ad_info.get('department', '')
                        event.ad_title = ad_info.get('title', '')
                        event.ad_display_name = ad_info.get('display_name', '')

                # Enriquecimento GeoIP
                if src_ip and src_ip != '0.0.0.0':
                    geo_info = geoip_client.get_location(src_ip)
                    if geo_info:
                        event.src_country = geo_info.get('country_name', '')
                
                if dst_ip and dst_ip != '0.0.0.0':
                    geo_info = geoip_client.get_location(dst_ip)
                    if geo_info:
                        event.dst_country = geo_info.get('country_name', '')

                # Campos específicos por subtipo e campos comuns que podem vir de lugares diferentes
                event.action = log.get('action', '')
                
                if subtype['name'] == 'ips':
                    event.attack_name = log.get('attack', '')
                    event.attack_id = log.get('attackid', '')
                    event.cve = log.get('cve', '')
                elif subtype['name'] == 'antivirus':
                    event.virus_name = log.get('virus', '')
                    event.file_name = log.get('filename', '')
                    event.file_hash = log.get('checksum', '')
                elif subtype['name'] == 'webfilter':
                    event.url = urllib.parse.unquote(log.get('url', ''))
                    event.category = log.get('catdesc', '')
                    # event.action já mapeado acima


                try:
                    event.save()
                    count_new += 1
                except IntegrityError as e:
                    logger.warning(f"IntegrityError saving event {event_id_raw}: {e}")
                except Exception as e:
                    logger.error(f"Error saving event {event_id_raw}: {e}")
            
            summary[subtype['name']] = f"Imported {count_new} events"

        return f"Coleta concluída: {json.dumps(summary)}"

    except Exception as e:
        logger.error(f"Erro na task fetch_security_events_task: {e}", exc_info=True)
        return f"Error: {e}"
        
    finally:
        release_lock()


@shared_task(name='Coleta de Eventos IPS')
def fetch_ips_task():
    return fetch_security_events_task(target_subtype='ips')


@shared_task(name='Coleta de Eventos Antivirus')
def fetch_antivirus_task():
    return fetch_security_events_task(target_subtype='antivirus')


@shared_task(name='Coleta de Eventos Web Filter')
def fetch_webfilter_task():
    return fetch_security_events_task(target_subtype='webfilter')
