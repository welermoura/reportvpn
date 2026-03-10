from celery import shared_task
from django.utils import timezone
from django.db.models import Q
from django.core.cache import cache
from dateutil.parser import parse
from integrations.fortianalyzer import FortiAnalyzerClient
from integrations.ad import ActiveDirectoryClient
from vpn_logs.models import VPNLog
import datetime
import logging
import pytz
import time

logger = logging.getLogger(__name__)

@shared_task(name='vpn_logs.tasks.daily_fidelity_vpn_report_task')
def daily_fidelity_vpn_report_task(target_date_str=None):
    """
    Relatório de Fidelidade VPN (D-1) Refinado:
    Consolida os logs do dia anterior usando logid_list de tráfego para precisão total.
    """
    logger.info("Iniciando Relatório de Fidelidade VPN (D-1) Refinado...")
    fa_client = FortiAnalyzerClient()
    ad_client = ActiveDirectoryClient()
    
    brt = pytz.timezone('America/Sao_Paulo')
    if target_date_str:
        target_dt = parse(target_date_str)
    else:
        now_local = datetime.datetime.now(brt)
        target_dt = now_local - datetime.timedelta(days=1)
    
    start_time = target_dt.replace(hour=0, minute=0, second=0, microsecond=0)
    end_time = target_dt.replace(hour=23, minute=59, second=59, microsecond=999999)
    
    logger.info(f"Processando período: {start_time} até {end_time}")

    # Janelas de 4 horas (6 janelas) para evitar timeouts e garantir captura total
    intervals = []
    curr = start_time
    while curr < end_time:
        next_curr = curr + datetime.timedelta(hours=4)
        intervals.append((curr, min(next_curr, end_time)))
        curr = next_curr

    import re
    ip_pattern = re.compile(r'^\d{1,3}(\.\d{1,3}){3}$')

    COUNTRY_MAP = {
        'brazil': 'BR', 'united states': 'US', 'argentina': 'AR', 
        'mexico': 'MX', 'chile': 'CL', 'colombia': 'CO', 'peru': 'PE',
        'paraguay': 'PY', 'uruguay': 'UY', 'canada': 'CA', 'germany': 'DE',
        'france': 'FR', 'united kingdom': 'GB', 'spain': 'ES', 'portugal': 'PT'
    }

    all_logs_data = []
    for i, (s_part, e_part) in enumerate(intervals, 1):
        logger.info(f"Janela {i}/{len(intervals)}: {s_part.strftime('%H:%M')} - {e_part.strftime('%H:%M')}")
        
        tid = None
        for attempt in range(3):
            try:
                # Utiliza o filtro matador para pegar APENAS túneis SSL, resolvendo o problema de ruído IPsec
                tid = fa_client.start_log_task(
                    log_type="event", 
                    start_time=s_part, 
                    end_time=e_part, 
                    limit=5000, 
                    log_filter='tunneltype=="ssl-tunnel" or action=="ssl-login-success"'
                )
                if tid: break
            except Exception as e:
                logger.warning(f"Tentativa {attempt+1} falhou para janela {i}: {e}")
                time.sleep(5)
        
        if not tid:
            continue

        time.sleep(10) 
        
        offset = 0
        batch_size = 150
        while offset < 5000:
            try:
                response = None
                for inner_attempt in range(3):
                    try:
                        response = fa_client.get_task_results(tid, limit=batch_size, offset=offset)
                        if response: break
                    except:
                        time.sleep(3)
                
                if not response: break
                
                batch = []
                data_wrap = response.get('result', {})
                if isinstance(data_wrap, list) and len(data_wrap) > 0:
                    batch = data_wrap[0].get('data', [])
                elif isinstance(data_wrap, dict):
                    batch = data_wrap.get('data', [])
                
                if not batch: break
                all_logs_data.extend(batch)
                offset += len(batch)
                if len(batch) < batch_size: break
                time.sleep(0.3)
            except:
                break

    if not all_logs_data:
        logger.warning(f"Nenhum log de event/vpn encontrado para {target_dt.date()}.")
        return f"No logs found for {target_dt.date()}"

    tunnels = {}
    for log in all_logs_data:
        u = log.get('user') or log.get('xauthuser') or log.get('remuser')
        if not u or u == 'N/A' or u == 'unknown':
            continue
            
        # Descarta acessos cujo usuário reportado é apenas um endereço IP (túneis Site-to-Site)
        if ip_pattern.match(u):
            continue
            
        # Grupos de sessão para extrair o máximo acumulado (e não somar tudo)
        tunnelid = str(log.get('tunnelid') or log.get('sessionid') or '')
        if not tunnelid:
            tunnelid = f"{u}_{log.get('remip', '')}"
            
        if tunnelid not in tunnels:
            tunnels[tunnelid] = {
                'user': u,
                'ip': log.get('remip') or log.get('srcip') or '0.0.0.0',
                'dur': 0, 'vol_in': 0, 'vol_out': 0,
                'last_time': f"{log.get('date', '')} {log.get('time', '')}",
                'raw_log': log
            }
            
        curr_ts = f"{log.get('date', '')} {log.get('time', '')}"
        if curr_ts > tunnels[tunnelid]['last_time']:
            tunnels[tunnelid]['last_time'] = curr_ts
            tunnels[tunnelid]['raw_log'] = log

        # FA event logs mandam status cumulativos; devemos pegar o MÁXIMO daquela sessão
        try:
            d = int(log.get('duration', 0))
            if d > tunnels[tunnelid]['dur']: tunnels[tunnelid]['dur'] = d
            vi = int(log.get('rcvdbyte', 0))
            if vi > tunnels[tunnelid]['vol_in']: tunnels[tunnelid]['vol_in'] = vi
            vo = int(log.get('sentbyte', 0))
            if vo > tunnels[tunnelid]['vol_out']: tunnels[tunnelid]['vol_out'] = vo
        except: pass

    # Agrega perfeitamente tunnelids em um dia para um único usuário/IP (Dashboard Report View)
    report_data = {}
    for tid, t_data in tunnels.items():
        key = (t_data['user'].lower(), t_data['ip'])
        
        if key not in report_data:
            report_data[key] = {
                'user': t_data['user'], 'ip': t_data['ip'], 
                'dur': 0, 'vol_in': 0, 'vol_out': 0, 'conns': 0,
                'last_time': t_data['last_time'],
                'raw_log': t_data['raw_log']
            }
            
        report_data[key]['dur'] += t_data['dur']
        report_data[key]['vol_in'] += t_data['vol_in']
        report_data[key]['vol_out'] += t_data['vol_out']
        report_data[key]['conns'] += 1
        
        if t_data['last_time'] > report_data[key]['last_time']:
            report_data[key]['last_time'] = t_data['last_time']
            report_data[key]['raw_log'] = t_data['raw_log']

    count_saved = 0
    date_str_key = target_dt.strftime('%Y%m%d')
    for (u_key, ip_key), data in report_data.items():
        session_id = f"fidelity_{date_str_key}_{u_key}_{ip_key.replace('.', '_')}"
        try:
            clean_user = data['user'].split('\\')[-1]
            ad_info = ad_client.get_user_info(clean_user) or {}
            
            try:
                last_conn_dt = parse(data['last_time'])
                if timezone.is_naive(last_conn_dt):
                    last_conn_dt = timezone.make_aware(last_conn_dt)
                last_conn_dt = last_conn_dt.astimezone(pytz.UTC)
            except:
                last_conn_dt = timezone.now()

            import urllib.parse
            fa_country = urllib.parse.unquote(str(data['raw_log'].get('srccountry', '') or data['raw_log'].get('remcountry', '')).strip())
            fa_city = urllib.parse.unquote(str(data['raw_log'].get('srccity', '') or data['raw_log'].get('remcity', '')).strip())
            country_name_val = fa_country if fa_country.lower() not in ['reserved', 'n/a'] else ''
            country_code_val = COUNTRY_MAP.get(country_name_val.lower(), '')

            VPNLog.objects.update_or_create(
                session_id=session_id,
                defaults={
                    'user': data['user'],
                    'source_ip': data['ip'],
                    'start_time': last_conn_dt,
                    'start_date': target_dt.date(),
                    'duration': data['dur'],
                    'bandwidth_in': data['vol_in'],
                    'bandwidth_out': data['vol_out'],
                    'status': 'closed',
                    'raw_data': {
                        **data['raw_log'],
                        'vpntype': 'ssl-tunnel',
                        'tunneltype': 'ssl-tunnel',
                        'last_activity': data['last_time'],
                        'conns': data['conns']
                    },
                    'ad_department': ad_info.get('department'),
                    'ad_email': ad_info.get('email'),
                    'ad_title': ad_info.get('title'),
                    'ad_display_name': ad_info.get('display_name'),
                    'city': fa_city,
                    'country_name': country_name_val,
                    'country_code': country_code_val,
                    'last_activity': last_conn_dt
                }
            )
            count_saved += 1
        except Exception as e:
            logger.error(f"Erro ao salvar fidelidade {u_key}: {e}")

    logger.info(f"Concluído. {count_saved} registros salvos.")
    return f"Saved {count_saved} logs for {target_dt.date()}"

LOCK_EXPIRE = 60 * 10  # Lock expires in 10 minutes

@shared_task(bind=True, name='vpn_logs.tasks.fetch_vpn_logs_task')
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

        # Load Config once
        from integrations.models import FortiAnalyzerConfig
        try:
            config = FortiAnalyzerConfig.load()
            if not config.is_enabled:
                logger.info("Coleta via API (Polling) do FortiAnalyzer desativada nas configurações.")
                return "Disabled"
            trusted_countries_list = [c.strip().upper() for c in config.trusted_countries.split(',')]
        except:
            trusted_countries_list = []
            config = None

        # Mapeamento estático leve para os países mais comuns
        COUNTRY_MAP = {
            'brazil': 'BR', 'united states': 'US', 'argentina': 'AR', 
            'mexico': 'MX', 'chile': 'CL', 'colombia': 'CO', 'peru': 'PE',
            'paraguay': 'PY', 'uruguay': 'UY', 'canada': 'CA', 'germany': 'DE',
            'france': 'FR', 'united kingdom': 'GB', 'spain': 'ES', 'portugal': 'PT'
        }

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
        filter_str = 'subtype=="vpn"'
        
        tid = fa_client.start_log_task(log_type="event", start_time=start_date, limit=fetch_limit, log_filter=filter_str)
        
        if not tid:
            error_msg = 'Falha ao obter TID do FortiAnalyzer.'
            logger.error(error_msg)
            return error_msg
            
        logger.info(f"Task iniciada no FA. TID: {tid}")
        
        # Wait for FA processing
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
                start_time_log = parse(f"{log_date} {log_time}")
                if timezone.is_naive(start_time_log):
                    start_time_log = timezone.make_aware(start_time_log)

                # Fix: Adjust for FA being 1 hour ahead
                start_time_log = start_time_log - datetime.timedelta(hours=1)
            except:
                start_time_log = timezone.now()

            duration = int(log.get('duration', 0))
            end_time = start_time_log + datetime.timedelta(seconds=duration)
            
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
                    status = 'active' 

                if action == 'tunnel-stats':
                    possible_log = None
                    if source_ip and source_ip != '0.0.0.0':
                        possible_log = VPNLog.objects.filter(source_ip=source_ip, status='active', start_time__lte=start_time_log).order_by('-start_time').first()
                    
                    if not possible_log and username and username not in ['unknown', 'N/A']:
                        possible_log = VPNLog.objects.filter(user=username, status='active', start_time__lte=start_time_log).order_by('-start_time').first()

                    if possible_log:
                        offset_duration = int(possible_log.raw_data.get('_duration_offset', 0))
                        real_duration = duration - offset_duration
                        if real_duration < 0: real_duration = 0
                        if real_duration > (possible_log.duration or 0):
                            possible_log.duration = real_duration
                            possible_log.end_time = possible_log.start_time + datetime.timedelta(seconds=real_duration)
                            possible_log.last_activity = start_time_log
                            possible_log.save(update_fields=['duration', 'end_time', 'last_activity'])
                        elif start_time_log > (possible_log.last_activity or possible_log.start_time):
                            possible_log.last_activity = start_time_log
                            possible_log.save(update_fields=['last_activity'])
                        continue
                
                try:
                    ad_info = {}
                    if username and username not in ['unknown', 'N/A']:
                        clean_user = username.split('\\')[-1]
                        ad_info = ad_client.get_user_info(clean_user) or {}

                    import urllib.parse
                    fa_country = urllib.parse.unquote(str(log.get('srccountry', '') or log.get('remcountry', '')).strip())
                    fa_city = urllib.parse.unquote(str(log.get('srccity', '') or log.get('remcity', '')).strip())
                    country_name_val = fa_country if fa_country.lower() not in ['reserved', 'n/a'] else ''
                    country_code_val = COUNTRY_MAP.get(country_name_val.lower(), '')
                    
                    log_entry, created = VPNLog.objects.update_or_create(
                        session_id=session_id,
                        defaults={
                            'user': username,
                            'source_ip': source_ip,
                            'start_time': start_time_log,
                            'start_date': start_time_log.date(),
                            'end_time': end_time,
                            'duration': duration,
                            'bandwidth_in': int(log.get('rcvdbyte', 0)),
                            'bandwidth_out': int(log.get('sentbyte', 0)),
                            'status': status,
                            'raw_data': log,
                            'ad_department': ad_info.get('department'),
                            'ad_email': ad_info.get('email'),
                            'ad_title': ad_info.get('title'),
                            'ad_display_name': ad_info.get('display_name'),
                            'is_suspicious': False,
                            'city': fa_city,
                            'country_name': country_name_val,
                            'country_code': country_code_val,
                            'last_activity': start_time_log
                        }
                    )
                    if not created:
                        if status == 'closed' and log_entry.status != 'closed':
                            log_entry.status = 'closed'
                            log_entry.duration = duration
                            log_entry.end_time = end_time
                            log_entry.last_activity = start_time_log
                            log_entry.save(update_fields=['status', 'duration', 'end_time', 'last_activity'])
                        elif start_time_log > (log_entry.last_activity or log_entry.start_time):
                            log_entry.last_activity = start_time_log
                            log_entry.save(update_fields=['last_activity'])
                    else:
                        count_new += 1

                except Exception as e:
                    logger.error(f"Erro ao processar log vpn {session_id}: {e}")
                    continue

            elif action in ['negotiate-error', 'auth-failure', 'ssl-login-fail', 'ipsec-login-fail']:
                from vpn_logs.models import VPNFailure
                from security_events.models import SecurityEvent
                
                import urllib.parse
                fa_country_fail = urllib.parse.unquote(str(log.get('srccountry', '') or log.get('remcountry', '')).strip())
                fa_city_fail = urllib.parse.unquote(str(log.get('srccity', '') or log.get('remcity', '')).strip())

                if fa_country_fail and fa_country_fail.lower() not in ['reserved', 'n/a']:
                    country_name_fail = fa_country_fail
                    country_code_fail = COUNTRY_MAP.get(fa_country_fail.lower(), '')
                    city_fail = fa_city_fail
                else:
                    country_name_fail = ''
                    country_code_fail = ''
                    city_fail = ''

                reason = log.get('reason', action)
                
                if not VPNFailure.objects.filter(
                    user=username, 
                    source_ip=source_ip, 
                    timestamp=start_time_log, 
                    reason=reason
                ).exists():
                    VPNFailure.objects.create(
                        user=username,
                        source_ip=source_ip,
                        timestamp=start_time_log,
                        reason=reason,
                        city=city_fail,
                        country_code=country_code_fail,
                        raw_data=log
                    )
                
                time_threshold = start_time_log - datetime.timedelta(minutes=5)
                failure_count = VPNFailure.objects.filter(
                    user=username,
                    source_ip=source_ip,
                    timestamp__gte=time_threshold
                ).count()
                
                if failure_count >= 5:
                    last_event = SecurityEvent.objects.filter(
                        event_type='ips',
                        attack_name='Brute Force Attack Detected',
                        username=username,
                        src_ip=source_ip,
                        timestamp__gte=time_threshold
                    ).exists()
                    
                    if not last_event:
                        import uuid
                        try:
                            SecurityEvent.objects.create(
                                event_id=str(uuid.uuid4()),
                                event_type='ips',
                                date=start_time_log.date(),
                                timestamp=start_time_log,
                                severity='critical',
                                username=username,
                                src_ip=source_ip,
                                dst_ip='0.0.0.0',
                                src_country=fa_country_fail or '',
                                action='block',
                                attack_name='Brute Force Attack Detected',
                                url=f"Detectadas {failure_count} falhas. Motivo: {reason}",
                                raw_log=str(log)
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

@shared_task(name='vpn_logs.tasks.consolidar_conexoes_virada_dia')
def consolidar_conexoes_virada_dia():
    """
    Task de consolidação noturna.
    Executada às 23:59. Particiona sessões ativas na virada da meia-noite.
    """
    logger.info("Iniciando consolidação de conexões de VPN da virada de dia...")
    now = timezone.now()
    active_logs = VPNLog.objects.filter(status='active', start_date=now.date()).exclude(session_id__contains='_midnight')
    
    count = 0
    for log in active_logs:
        original_session = log.session_id
        duration_today = (now - log.start_time).total_seconds()
        if duration_today < 0: duration_today = 0
            
        import uuid
        unique_suffix = f"_midnight_{log.start_date}_{uuid.uuid4().hex[:6]}"

        log.session_id = f"{original_session}{unique_suffix}"
        log.status = 'closed'
        log.end_time = now
        log.duration = int(duration_today)
        log.save(update_fields=['session_id', 'status', 'end_time', 'duration'])
        
        new_start = now
        new_raw = log.raw_data.copy() if isinstance(log.raw_data, dict) else {}
        new_raw['_duration_offset'] = int(new_raw.get('duration', 0) or 0) + int(duration_today)
        new_raw['_rcvd_offset'] = int(new_raw.get('rcvdbyte', 0) or 0) + log.bandwidth_in
        new_raw['_sent_offset'] = int(new_raw.get('sentbyte', 0) or 0) + log.bandwidth_out
        
        VPNLog.objects.create(
            session_id=original_session,
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
            is_suspicious=log.is_suspicious,
            last_activity=new_start
        )
        count += 1
        
    logger.info(f"Consolidação concluída. {count} sessões ativas particionadas.")
    return f"Consolidated {count} sessions"

@shared_task(name='vpn_logs.tasks.close_stale_sessions_task')
def close_stale_sessions_task():
    """
    Fecha sessões inativas por mais de 12 minutos.
    """
    logger.info("Iniciando verificação de sessões expiradas...")
    now = timezone.now()
    timeout_threshold = now - datetime.timedelta(minutes=12)
    
    stale_sessions = VPNLog.objects.filter(
        status__in=['active', 'tunnel-up']
    ).filter(
        Q(last_activity__lt=timeout_threshold) | 
        Q(last_activity__isnull=True, start_time__lt=timeout_threshold)
    )
    
    count = stale_sessions.count()
    if count > 0:
        for session in stale_sessions:
            end_ts = session.last_activity if session.last_activity else (session.start_time + datetime.timedelta(seconds=session.duration or 0))
            if end_ts > now: end_ts = now
            session.status = 'closed'
            session.end_time = end_ts
            if session.start_time:
                session.duration = int((end_ts - session.start_time).total_seconds())
            session.save(update_fields=['status', 'end_time', 'duration'])
    return f"Closed {count} stale sessions"
