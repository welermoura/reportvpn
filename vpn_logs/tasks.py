from celery import shared_task
from django.utils import timezone
from django.core.cache import cache
from dateutil.parser import parse
from integrations.fortianalyzer import FortiAnalyzerClient
from integrations.ad import ActiveDirectoryClient
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
        
        # Fetch logs with offset pagination due to FA hard limits (usually 100)
        logs_data = []
        offset = 0
        batch_limit = 100 # Default/Max safe page size for FA

        while offset < fetch_limit:
            response = fa_client.get_task_results(tid, limit=batch_limit, offset=offset)
            
            if not response:
                break

            batch_logs = []
            if 'result' in response:
                res = response['result']
                if isinstance(res, dict):
                    batch_logs = res.get('data', [])
                elif isinstance(res, list) and len(res) > 0:
                    batch_logs = res[0].get('data', [])
            elif isinstance(response, list):
                batch_logs = response
            elif 'data' in response:
                batch_logs = response['data']

            if not batch_logs:
                break # No more data returned

            logs_data.extend(batch_logs)
            offset += len(batch_logs)
            
            if len(batch_logs) < batch_limit:
                break # Reached the end before fetch_limit

        logger.info(f'Encontrados {len(logs_data)} registros brutos após paginação.')
        
        count_new = 0
        for log in logs_data:
            session_id = str(log.get('sessionid') or '')
            if not session_id or session_id == '0' or session_id.lower() == 'none':
                session_id = str(log.get('tunnelid') or '')
            if not session_id or session_id == '0' or session_id.lower() == 'none':
                session_id = f"{log.get('date', '')}-{log.get('time', '')}-{log.get('user', '')}"
            
            existing_log = VPNLog.objects.filter(session_id=session_id).first()

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
            if action in ['tunnel-up', 'tunnel-stats', 'tunnel-down']:
                if action == 'tunnel-up':
                    status = 'active'
                elif action == 'tunnel-down':
                    status = 'closed'
                elif action == 'tunnel-stats':
                    status = 'active' # Intermediate stat means it's still active or was active recently

                if existing_log:
                    # Se for uma sessão consolidada na virada do dia, ela terá um offset p/ subtrair os dados acumulados de ontem
                    offset_duration = int(existing_log.raw_data.get('_duration_offset', 0))
                    offset_rcvd = int(existing_log.raw_data.get('_rcvd_offset', 0))
                    offset_sent = int(existing_log.raw_data.get('_sent_offset', 0))

                    real_duration = duration - offset_duration
                    if real_duration < 0: real_duration = 0
                    
                    real_rcvd = int(log.get('rcvdbyte', 0)) - offset_rcvd
                    if real_rcvd < 0: real_rcvd = 0
                        
                    real_sent = int(log.get('sentbyte', 0)) - offset_sent
                    if real_sent < 0: real_sent = 0

                    if action == 'tunnel-stats':
                        # Para eventos intermediários, usamos a duração real
                        if real_duration > (existing_log.duration or 0):
                            existing_log.duration = real_duration
                            existing_log.end_time = existing_log.start_time + datetime.timedelta(seconds=real_duration)
                            existing_log.save(update_fields=['duration', 'end_time'])
                        # Não precisamos processar bandwidth aqui (normalmente tunnel-stats vem com bytes zerados ou acumulados)
                        continue

                    # Lógica original para tunnel-up / tunnel-down (com offsets)
                    # Session already exists, update if the new event provides more duration or closes the session
                    existing_duration = existing_log.duration or 0
                    if real_duration > existing_duration or (real_duration == existing_duration and status == 'closed' and existing_log.status != 'closed'):
                        existing_log.duration = real_duration
                        existing_log.end_time = existing_log.start_time + datetime.timedelta(seconds=real_duration)
                        existing_log.bandwidth_in = real_rcvd
                        existing_log.bandwidth_out = real_sent
                        if status == 'closed':
                            existing_log.status = 'closed'
                        existing_log.bypass_suspicious_check = True
                        existing_log.save(update_fields=['duration', 'end_time', 'bandwidth_in', 'bandwidth_out', 'status'])
                    continue
                else:
                    # Nenhuma sessão encontrada por session_id; tentar associar tunnel-stats a uma sessão ativa
                    if action == 'tunnel-stats':
                        possible_log = None
                        # Busca por IP ou por Usuário (caso o IP venha zerado no log de estatística)
                        if source_ip and source_ip != '0.0.0.0':
                            possible_log = VPNLog.objects.filter(source_ip=source_ip, status='active', start_time__lte=start_time).order_by('-start_time').first()
                        
                        if not possible_log and username and username not in ['unknown', 'N/A']:
                            possible_log = VPNLog.objects.filter(user=username, status='active', start_time__lte=start_time).order_by('-start_time').first()

                        if possible_log:
                            offset_duration = int(possible_log.raw_data.get('_duration_offset', 0))
                            real_duration = duration - offset_duration
                            if real_duration < 0: real_duration = 0
                            
                            if real_duration > (possible_log.duration or 0):
                                possible_log.duration = real_duration
                                possible_log.end_time = possible_log.start_time + datetime.timedelta(seconds=real_duration)
                                possible_log.save(update_fields=['duration', 'end_time'])
                            continue

                # Below is the logic for NEW sessions exclusively
                # Enrich with AD
                ad_info = {}
                if username and username not in ['unknown', 'N/A']:
                    clean_user = username.split('\\')[-1]
                    ad_info = ad_client.get_user_info(clean_user) or {}

                # Enrich com dados geográficos — campos nativos do FortiGate
                fa_country = str(log.get('srccountry', '') or log.get('remcountry', '')).strip()
                fa_city = str(log.get('srccity', '') or log.get('remcity', '')).strip()
                
                # Mapeamento estático leve para os países mais comuns (compatibilidade)
                COUNTRY_MAP = {
                    'brazil': 'BR', 'united states': 'US', 'argentina': 'AR', 
                    'mexico': 'MX', 'chile': 'CL', 'colombia': 'CO', 'peru': 'PE',
                    'paraguay': 'PY', 'uruguay': 'UY', 'canada': 'CA', 'germany': 'DE',
                    'france': 'FR', 'united kingdom': 'GB', 'spain': 'ES', 'portugal': 'PT'
                }

                country_name_val = fa_country if fa_country.lower() not in ['reserved', 'n/a'] else ''
                country_code_val = COUNTRY_MAP.get(country_name_val.lower(), '')
                city_val = fa_city

                # Determine suspicious
                is_suspicious = False
                if country_code_val:
                    if country_code_val.upper() not in trusted_countries_list:
                        is_suspicious = True
                elif country_name_val and trusted_countries_list:
                    # Fallback para string match
                    is_suspicious = not any(v in country_name_val.upper() for v in trusted_countries_list)

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
                    city=city_val,
                    country_name=country_name_val,
                    country_code=country_code_val,
                    is_suspicious=is_suspicious
                )
                # Bypass DB check in save() method
                log_entry.bypass_suspicious_check = True
                log_entry.save()
            
            # --- Lógica de Falha (VPNFailure & Brute Force) ---
            elif action in ['negotiate-error', 'auth-failure', 'ssl-login-fail', 'ipsec-login-fail']:
                from vpn_logs.models import VPNFailure
                from security_events.models import SecurityEvent
                
                # Enrich GeoIP para Failure — prioriza log nativo
                fa_country_fail = str(log.get('srccountry', '') or log.get('remcountry', '')).strip()
                fa_city_fail = str(log.get('srccity', '') or log.get('remcity', '')).strip()

                if fa_country_fail and fa_country_fail.lower() not in ['reserved', 'n/a']:
                    country_name_fail = fa_country_fail
                    country_code_fail = COUNTRY_MAP.get(fa_country_fail.lower(), '')
                    city_fail = fa_city_fail
                else:
                    country_name_fail = ''
                    country_code_fail = ''
                    city_fail = ''

                reason = log.get('reason', action)
                
                VPNFailure.objects.create(
                    user=username,
                    source_ip=source_ip,
                    timestamp=start_time,
                    reason=reason,
                    city=city_fail,
                    country_code=country_code_fail,
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
                        import uuid
                        try:
                            SecurityEvent.objects.create(
                                event_id=str(uuid.uuid4()),
                                event_type='ips', # Falta 'bruteforce' no model, usando 'ips' temporariamente
                                date=start_time.date(),
                                timestamp=start_time,
                                severity='critical',
                                username=username,
                                src_ip=source_ip,
                                dst_ip='0.0.0.0',
                                src_country=fa_country_fail or geo_info.get('country_code', ''),
                                action='block', # Recomendação
                                attack_name='Brute Force Attack Detected',
                                # Sem details pois o model nao suporta, vamos por na url ou log bruto
                                url=f"Detectadas {failure_count} falhas. Motivo: {reason}",
                                raw_log=str(log) # O model exige textfield
                            )
                        except Exception as e:
                            logger.error(f"Failed to create Brute Force SecurityEvent: {e}")
            
            count_new += 1

        logger.info(f"Processamento concluido. {count_new} novos logs.")
        return f"Imported {count_new} logs"

    except Exception as e:
        logger.error(f"Erro na task fetch_vpn_logs_task: {e}", exc_info=True)
        return f"Error: {e}"
        
    finally:
        release_lock()

@shared_task(name='Consolidar Conexões VPN à Meia-Noite')
def consolidar_conexoes_virada_dia():
    """
    Task de consolidação noturna.
    Executada às 23:59. Seu objetivo é garantir que a duração das conexões
    ativas seja computada corretamente no dia do início, separando a sessão na virada da meia-noite.
    """
    logger.info("Iniciando consolidação de conexões de VPN da virada de dia...")
    now = timezone.now()
    # Buscamos logs ativos que começaram HOJE e ainda não foram consolidados
    active_logs = VPNLog.objects.filter(status='active', start_date=now.date()).exclude(session_id__contains='_midnight')
    
    count = 0

    
    for log in active_logs:
        original_session = log.session_id
        
        # Calcular duração do dia corrente até agora (aprox 23:59)
        duration_today = (now - log.start_time).total_seconds()
        if duration_today < 0: 
            duration_today = 0
            
        import uuid
        unique_suffix = f"_midnight_{log.start_date}_{uuid.uuid4().hex[:6]}"

        # 1. Fechar o log do dia atual
        log.session_id = f"{original_session}{unique_suffix}"
        log.status = 'closed'
        log.end_time = now
        log.duration = int(duration_today)
        log.save(update_fields=['session_id', 'status', 'end_time', 'duration'])
        
        # 2. Re-criar o log para continuar contando amanhã
        new_start = now # Equivalente a 00:00:00 do dia seguinte ou 23:59:00
        
        # Injetar o offset em raw_data para que o fetch_vpn_logs subtraia o acumulado do FA
        new_raw = log.raw_data.copy() if isinstance(log.raw_data, dict) else {}
        
        new_raw['_duration_offset'] = int(new_raw.get('duration', 0) or 0) + int(duration_today)
        new_raw['_rcvd_offset'] = int(new_raw.get('rcvdbyte', 0) or 0) + log.bandwidth_in
        new_raw['_sent_offset'] = int(new_raw.get('sentbyte', 0) or 0) + log.bandwidth_out
        
        VPNLog.objects.create(
            session_id=original_session, # Mesma session ID p/ receber os updates do FA!
            user=log.user,
            source_ip=log.source_ip,
            start_time=new_start,
            start_date=new_start.date(),
            end_time=new_start,
            duration=0,
            bandwidth_in=0,
            bandwidth_out=0,
            status='active',
            raw_data=new_raw,
            ad_department=log.ad_department,
            ad_email=log.ad_email,
            ad_title=log.ad_title,
            ad_display_name=log.ad_display_name,
            city=log.city,
            country_name=log.country_name,
            country_code=log.country_code,
            is_suspicious=log.is_suspicious
        )
        count += 1
        
    logger.info(f"Consolidação concluída. {count} sessões ativas foram particionadas para o novo dia.")
    return f"Consolidated {count} sessions"
