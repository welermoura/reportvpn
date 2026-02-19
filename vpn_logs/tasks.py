from celery import shared_task
from django.utils import timezone
from django.core.cache import cache
from dateutil.parser import parse
from integrations.fortianalyzer import FortiAnalyzerClient
from integrations.ad import ActiveDirectoryClient
from integrations.geoip import GeoIPClient
from vpn_logs.models import VPNLog
import datetime
import logging

logger = logging.getLogger(__name__)

LOCK_EXPIRE = 60 * 10  # Lock expires in 10 minutes

@shared_task(bind=True, name='Coleta de Logs VPN')
def fetch_vpn_logs_task(self):
    lock_id = "fetch_vpn_logs_lock"
    acquire_lock = lambda: cache.add(lock_id, "true", LOCK_EXPIRE)
    release_lock = lambda: cache.delete(lock_id)

    if not acquire_lock():
        logger.warning("Task fetch_vpn_logs_task is already running.")
        return "Locked"

    try:
        logger.info("Starting fetch_vpn_logs_task...")
        
        fa_client = FortiAnalyzerClient()
        ad_client = ActiveDirectoryClient()
        geoip_client = GeoIPClient()

        # Load Trusted Countries once
        from integrations.models import FortiAnalyzerConfig
        try:
            config = FortiAnalyzerConfig.load()
            trusted_countries_list = [c.strip().upper() for c in config.trusted_countries.split(',')]
        except:
            trusted_countries_list = []

        # Configurações de busca
        days_ago = 365
        start_date = timezone.now() - datetime.timedelta(days=days_ago)
        fetch_limit = 10000 
        filter_str = 'subtype=="vpn" and (tunneltype=="ssl-tunnel" or tunneltype=="ssl-web")'
        
        tid = fa_client.start_log_task(log_type="event", start_time=start_date, limit=fetch_limit, log_filter=filter_str)
        
        if not tid:
            error_msg = 'Falha ao obter TID do FortiAnalyzer.'
            logger.error(error_msg)
            return error_msg
            
        logger.info(f"Task iniciada no FA. TID: {tid}")
        
        # Wait for FA processing
        import time
        time.sleep(15) 
        
        response = fa_client.get_task_results(tid, limit=fetch_limit)
        
        if not response:
            logger.warning('Nenhum dado retornado do FA.')
            return 'No data'

        logs_data = []
        if 'result' in response:
            res = response['result']
            if isinstance(res, dict):
                logs_data = res.get('data', [])
            elif isinstance(res, list) and len(res) > 0:
                logs_data = res[0].get('data', [])
        elif isinstance(response, list):
            logs_data = response
        elif 'data' in response:
            logs_data = response['data']
        
        logger.info(f'Encontrados {len(logs_data)} registros brutos.')
        
        count_new = 0
        for log in logs_data:
            session_id = str(log.get('sessionid', ''))
            if not session_id or session_id == '0':
                session_id = str(log.get('tunnelid', ''))
            if not session_id or session_id == '0':
                session_id = f"{log.get('date', '')}-{log.get('time', '')}-{log.get('user', '')}"
            
            if VPNLog.objects.filter(session_id=session_id).exists():
                continue

            username = log.get('user', 'unknown')
            if username == 'N/A':
                username = log.get('xauthuser', 'N/A')

            source_ip = log.get('remip')
            if not source_ip or source_ip == '0.0.0.0':
                source_ip = log.get('srcip', '0.0.0.0')

            try:
                log_date = log.get('date', '')
                log_time = log.get('time', '')
                start_time = parse(f"{log_date} {log_time}")
                if timezone.is_naive(start_time):
                    start_time = timezone.make_aware(start_time)

                # Fix: Adjust for FA being 1 hour ahead
                start_time = start_time - datetime.timedelta(hours=1)
            except:
                start_time = timezone.now()

            duration = int(log.get('duration', 0))
            end_time = start_time + datetime.timedelta(seconds=duration)
            
            # Determine status/action
            action = log.get('action', '')
            status = 'tunnel-down'
            
            # --- Lógica de Sucesso (VPNLog) ---
            if action in ['tunnel-up', 'tunnel-stats']:
                if action == 'tunnel-up':
                    status = 'active'
                elif action == 'tunnel-down':
                    status = 'closed'

                # Enrich with AD
                ad_info = {}
                if username and username not in ['unknown', 'N/A']:
                    clean_user = username.split('\\')[-1]
                    ad_info = ad_client.get_user_info(clean_user) or {}

                # Enrich with GeoIP
                geo_info = {}
                if source_ip and source_ip != '0.0.0.0':
                    geo_info = geoip_client.get_location(source_ip) or {}

                # Determine suspicious (Pre-calc for performance)
                is_suspicious = False
                if geo_info.get('country_code'):
                    code = geo_info.get('country_code').upper()
                    if code not in trusted_countries_list:
                        is_suspicious = True

                log_entry = VPNLog(
                    session_id=session_id,
                    user=username,
                    source_ip=source_ip,
                    start_time=start_time,
                    start_date=start_time.date(),
                    end_time=end_time,
                    duration=duration,
                    bandwidth_in=int(log.get('rcvdbyte', 0)),
                    bandwidth_out=int(log.get('sentbyte', 0)),
                    status=status,
                    raw_data=log,
                    ad_department=ad_info.get('department'),
                    ad_email=ad_info.get('email'),
                    ad_title=ad_info.get('title'),
                    ad_display_name=ad_info.get('display_name'),
                    city=geo_info.get('city'),
                    country_name=geo_info.get('country_name'),
                    country_code=geo_info.get('country_code'),
                    is_suspicious=is_suspicious
                )
                # Bypass DB check in save() method
                log_entry.bypass_suspicious_check = True
                log_entry.save()
            
            # --- Lógica de Falha (VPNFailure & Brute Force) ---
            elif action in ['negotiate-error', 'auth-failure', 'ssl-login-fail', 'ipsec-login-fail']:
                from vpn_logs.models import VPNFailure
                from security_events.models import SecurityEvent
                
                # Enrich GeoIP for Failure
                geo_info = {}
                if source_ip and source_ip != '0.0.0.0':
                    geo_info = geoip_client.get_location(source_ip) or {}

                reason = log.get('reason', action) # Use action as fallback reason
                
                VPNFailure.objects.create(
                    user=username,
                    source_ip=source_ip,
                    timestamp=start_time,
                    reason=reason,
                    city=geo_info.get('city'),
                    country_code=geo_info.get('country_code'),
                    raw_data=log
                )
                
                # --- BRUTE FORCE DETECTION ---
                # Regra: > 5 falhas nos últimos 5 minutos para mesmo user/ip
                time_threshold = start_time - datetime.timedelta(minutes=5)
                failure_count = VPNFailure.objects.filter(
                    user=username,
                    source_ip=source_ip,
                    timestamp__gte=time_threshold
                ).count()
                
                if failure_count >= 5:
                    # Verificar se já existe evento de Brute Force recente (evitar spam)
                    last_event = SecurityEvent.objects.filter(
                        event_type='bruteforce',
                        username=username,
                        src_ip=source_ip,
                        timestamp__gte=time_threshold
                    ).exists()
                    
                    if not last_event:
                        SecurityEvent.objects.create(
                            event_type='bruteforce',
                            timestamp=start_time,
                            severity='critical',
                            username=username,
                            src_ip=source_ip,
                            src_country=geo_info.get('country_code'),
                            action='block', # Recomendação
                            attack_name='Brute Force Attack Detected',
                            details=f"Detectadas {failure_count} falhas de login em 5 minutos. Motivo: {reason}",
                            raw_log=log
                        )
            
            count_new += 1

        logger.info(f"Processamento concluido. {count_new} novos logs.")
        return f"Imported {count_new} logs"

    except Exception as e:
        logger.error(f"Erro na task fetch_vpn_logs_task: {e}", exc_info=True)
        return f"Error: {e}"
        
    finally:
        release_lock()
