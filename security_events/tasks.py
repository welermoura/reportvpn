from celery import shared_task
from django.utils import timezone
from django.core.cache import cache
from django.db import IntegrityError
from dateutil.parser import parse
from integrations.fortianalyzer import FortiAnalyzerClient
from integrations.ad import ActiveDirectoryClient
from .models import SecurityEvent
import datetime
import logging
import json
import urllib.parse
import hashlib

logger = logging.getLogger(__name__)

LOCK_EXPIRE = 60 * 10  # Lock expires in 10 minutes

@shared_task(bind=True)
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

        # Load Config once
        from integrations.models import FortiAnalyzerConfig
        config = FortiAnalyzerConfig.load()
        if not config.is_enabled:
            logger.info("Coleta via API (Polling) do FortiAnalyzer (Security Events) desativada nas configurações.")
            return "Disabled"

        # Configurações de busca - focado apenas no dado recente (crons rodam a cada 30min)
        # Ajustado para 6 horas pelo fuso horário ser potencialmente distorcido entre FA e Django
        hours_ago = 6
        start_date = timezone.now() - datetime.timedelta(hours=hours_ago)
        fetch_limit = 5000
        
        # Subtipos para coletar
        all_subtypes = [
            {'name': 'ips', 'log_type': 'ips', 'filter': 'subtype=="ips"'},
            {'name': 'antivirus', 'log_type': 'virus', 'filter': 'subtype=="virus"'},
            {'name': 'webfilter', 'log_type': 'webfilter', 'filter': 'subtype=="webfilter"'},
            {'name': 'app-control', 'log_type': 'traffic', 'filter': 'app!="" and app!="unscanned" and app!="unknown"'}
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

                # Enriquecimento de Países usando nativamente os logs do FortiGate
                fa_src_country = str(log.get('srccountry', '')).strip()
                fa_src_city = str(log.get('srccity', '')).strip()
                fa_dst_country = str(log.get('dstcountry', '')).strip()

                if fa_src_country and fa_src_country.lower() not in ['', 'reserved', 'n/a']:
                    event.src_country = fa_src_country

                if fa_dst_country and fa_dst_country.lower() not in ['', 'reserved', 'n/a']:
                    event.dst_country = fa_dst_country

                # Campos específicos por subtipo e campos comuns que podem vir de lugares diferentes
                raw_action = str(log.get('action', '')).lower()
                
                # Normaliza actions do Log Bruto para casar com os Filtros do App/FrontEnd
                if raw_action in ['accept', 'passthrough', 'allowed', 'ip-conn', 'close', 'client-rst', 'server-rst', 'timeout']:
                    event.action = 'pass' if subtype['name'] == 'app-control' else 'passthrough'
                elif raw_action in ['deny', 'block', 'blocked', 'clear_session', 'reset']:
                    event.action = 'blocked'
                else:
                    event.action = raw_action
                
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
                elif subtype['name'] == 'app-control':
                    app_raw = str(log.get('app', '')).strip()
                    cat_raw = str(log.get('appcat', '')).strip()
                    
                    # Ignorar ruídos de rede genérica do Fortigate para limpar o painel AppControl
                    if app_raw.lower() in ['', 'unscanned', 'unknown'] and cat_raw.lower() in ['', 'unscanned', 'unknown']:
                        continue
                    
                    if not app_raw and cat_raw:
                        app_raw = cat_raw # fallback nome=categoria
                    elif not app_raw or app_raw.lower() == 'unscanned':
                        app_raw = "Tráfego Genérico"
                        
                    if not cat_raw or cat_raw.lower() == 'unscanned':
                        cat_raw = "Geral"
                        
                    event.app_name = app_raw
                    event.app_category = cat_raw
                    event.app_risk = str(log.get('apprisk', 'low'))
                    
                    # URL/Hostname extraction for App Control
                    hostname = log.get('hostname', '')
                    url_path = log.get('url', '')
                    if hostname:
                        event.url = f"{hostname}{url_path}" if url_path else hostname
                    elif url_path:
                        event.url = url_path

                    # Bytes conversion (ensure 0 instead of None if we want data to show in charts)
                    # Note: UTM logs might not have bytes, but we try to capture them if present
                    try:
                        event.bytes_in = int(log.get('rcvdbyte', 0))
                    except (ValueError, TypeError):
                        event.bytes_in = 0
                        
                    try:
                        event.bytes_out = int(log.get('sentbyte', 0))
                    except (ValueError, TypeError):
                        event.bytes_out = 0


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


@shared_task(name='Coleta de Eventos App Control')
def fetch_appcontrol_task():
    return fetch_security_events_task(target_subtype='app-control')


@shared_task(name='Varredura de Risco LDAP (Radar AD)')
def run_ad_radar_scan_task():
    """
    Executa a verificação completa de inatividade e caminhos de delegacão do AD (Radar AD).
    Roda em Background para não estourar timeout do proxy Nginx.
    """
    from security_events.api.radar_scanner import RadarScanner
    logger.info("Iniciando Radar AD Task via Celery...")
    try:
        scanner = RadarScanner()
        snap = scanner.run_scan()
        logger.info(f"Scan finalizado com sucesso. ID Snapshot: {snap.id}")
        return f"Scan concluído. Contas Críticas: {snap.inactive_privileged_count}"
    except Exception as e:
        logger.error(f"Falha ao executar Radar AD Task: {str(e)}", exc_info=True)
        return f"Erro: {str(e)}"
