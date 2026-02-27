from django.utils import timezone
from datetime import timedelta
from django.db import models
from django.db.models import Count, Q, Case, When, IntegerField, Sum
from security_events.models import SecurityEvent
from vpn_logs.models import VPNLog, VPNFailure
from .models import UserRiskScore, RiskEvent
import logging

logger = logging.getLogger(__name__)

class RiskScoringService:
    @staticmethod
    def update_all_users(days=7):
        """
        Gera o score de risco para todos os usuários que tiveram atividade recente usando agregações otimizadas.
        """
        start_date = timezone.now() - timedelta(days=days)
        logger.info(f"Iniciando cálculo de score otimizado a partir de {start_date}")
        
        # Dicionário para acumular dados por usuário: {username: {'score': 0, 'events': []}}
        user_data = {}

        def get_user_entry(username):
            if not username: return None
            if username not in user_data:
                user_data[username] = {'score': 0, 'events': []}
            return user_data[username]

        # 1. Agregações de SecurityEvents (WebFilter, IPS, AV)
        # WebFilter: bloqueios (2 pts cada, limitado a 100)
        web_blocks = SecurityEvent.objects.filter(
            event_type='webfilter', 
            action='blocked', 
            timestamp__gte=start_date
        ).values('username').annotate(count=Count('id')).order_by()
        
        for item in web_blocks:
            u = item['username']
            count = item['count']
            if not u: continue
            weight = min(count * 2, 100)
            entry = get_user_entry(u)
            entry['score'] += weight
            entry['events'].append({
                'source': 'webfilter',
                'weight': weight,
                'desc': f"Web Filter: {count} bloqueios (Capado em 100 pts)",
                'ts': timezone.now()
            })

        # IPS: Critical=25, High=15
        ips_aggr = SecurityEvent.objects.filter(
            event_type='ips', 
            timestamp__gte=start_date,
            severity__in=['critical', 'high']
        ).values('username', 'severity').annotate(count=Count('id')).order_by()

        for item in ips_aggr:
            u = item['username']
            sev = item['severity']
            count = item['count']
            if not u: continue
            
            weight_unit = 25 if sev == 'critical' else 15
            weight = weight_unit * count
            entry = get_user_entry(u)
            entry['score'] += weight
            entry['events'].append({
                'source': 'ips',
                'weight': weight,
                'desc': f"IPS: {count} eventos de severidade {sev}",
                'ts': timezone.now()
            })

        # Antivírus: 30 pts fixo por evento
        av_aggr = SecurityEvent.objects.filter(
            event_type='antivirus', 
            timestamp__gte=start_date
        ).values('username').annotate(count=Count('id')).order_by()

        for item in av_aggr:
            u = item['username']
            count = item['count']
            if not u: continue
            weight = 30 * count
            entry = get_user_entry(u)
            entry['score'] += weight
            entry['events'].append({
                'source': 'antivirus',
                'weight': weight,
                'desc': f"AV: {count} vírus detectados",
                'ts': timezone.now()
            })

        # 2. Agregações de VPN
        vpn_aggr = VPNLog.objects.filter(
            start_time__gte=start_date
        ).values('user').annotate(
            suspicious=Count('id', filter=Q(is_suspicious=True)),
            impossible=Count('id', filter=Q(impossible_travel=True))
        ).order_by()

        for item in vpn_aggr:
            u = item['user']
            if not u: continue
            
            if item['suspicious'] > 0:
                weight = 20 * item['suspicious']
                entry = get_user_entry(u)
                entry['score'] += weight
                entry['events'].append({
                    'source': 'vpn',
                    'weight': weight,
                    'desc': f"VPN: {item['suspicious']} acessos de países não confiáveis",
                    'ts': timezone.now()
                })
            
            if item['impossible'] > 0:
                weight = 40 * item['impossible']
                entry = get_user_entry(u)
                entry['score'] += weight
                
                # Buscar o detalhe da viagem impossível mais recente para este usuário no período
                last_travel = VPNLog.objects.filter(
                    user=u, 
                    impossible_travel=True, 
                    start_time__gte=start_date
                ).order_by('-start_time').first()
                
                desc = f"VPN: {item['impossible']} alertas de viagem impossível"
                if last_travel:
                    if last_travel.travel_details:
                        prev = last_travel.travel_details.get('previous', {})
                        curr = last_travel.travel_details.get('current', {})
                        hours = last_travel.travel_details.get('time_diff_hours', '?')
                        dist = last_travel.travel_details.get('distance_km', '?')
                        speed = last_travel.travel_details.get('speed_kmh', '?')
                        
                        # Formatação de tempo amigável (minutos se < 1h)
                        if isinstance(hours, (int, float)):
                            time_str = f"{int(hours * 60)} min" if hours < 1 else f"{hours}h"
                        else:
                            time_str = f"{hours}h"
                            
                        desc = f"Viagem Impossível: De {prev.get('city') or '?'}/{prev.get('code')} para {curr.get('city') or '?'}/{curr.get('code')} em {time_str} ({dist}km a {speed}km/h)"
                    else:
                        # Reconstrução on-the-fly para logs antigos ou sem JSON
                        # Garantir que buscamos um log com localização DIFERENTE para fazer sentido
                        prev_log = VPNLog.objects.filter(
                            user=u,
                            start_time__lt=last_travel.start_time,
                            country_code__isnull=False
                        ).exclude(
                            Q(id=last_travel.id) | 
                            Q(city=last_travel.city, country_code=last_travel.country_code)
                        ).order_by('-start_time').first()

                        if prev_log:
                            diff = last_travel.start_time - prev_log.start_time
                            minutes = int(diff.total_seconds() / 60)
                            time_str = f"{minutes} min" if minutes < 60 else f"{round(minutes/60, 1)}h"
                            
                            desc = f"Viagem Impossível: De {prev_log.city or '?'}/{prev_log.country_code} para {last_travel.city or '?'}/{last_travel.country_code} em {time_str}"
                        else:
                            loc = f"{last_travel.city or '?'}/{last_travel.country_code or '?'}"
                            desc = f"Viagem Impossível: Alerta em {loc}"

                entry['events'].append({
                    'source': 'vpn',
                    'weight': weight,
                    'desc': desc,
                    'ts': timezone.now()
                })

        # Falhas de Login: 15 pts se >= 10 falhas
        fail_aggr = VPNFailure.objects.filter(
            timestamp__gte=start_date
        ).values('user').annotate(count=Count('id')).order_by()

        for item in fail_aggr:
            u = item['user']
            count = item['count']
            if not u or count < 10: continue
            
            weight = 15
            entry = get_user_entry(u)
            entry['score'] += weight
            entry['events'].append({
                'source': 'vpn',
                'weight': weight,
                'desc': f"VPN: Brute Force detectado ({count} falhas)",
                'ts': timezone.now()
            })

        # 3. Persistência e Filtro AD
        from integrations.ad import ActiveDirectoryClient
        import re
        ad_client = ActiveDirectoryClient()
        results = []

        logger.info(f"Calculados dados para {len(user_data)} usuários. Iniciando validação AD...")

        for username, data in user_data.items():
            if username.lower() in ['unknown', 'n/a']: continue
            if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', username): continue

            # Validação AD (Essencial para filtrar ruído de IPs externos)
            clean_user = username.split('\\')[-1]
            if not ad_client.get_user_info(clean_user):
                # Se não está no AD e o score é alto, logamos (pode ser um admin local ou conta fake)
                if data['score'] > 50:
                    logger.warning(f"Usuário de alto risco ({data['score']}) ignorado (Not in AD): {username}")
                UserRiskScore.objects.filter(username=username).delete()
                continue

            # Persistência do Score
            score_obj, created = UserRiskScore.objects.get_or_create(username=username)
            old_score = score_obj.current_score
            score_obj.current_score = data['score']
            
            # Nível
            if data['score'] == 0: score_obj.risk_level = 'None'
            elif data['score'] < 30: score_obj.risk_level = 'Low'
            elif data['score'] < 70: score_obj.risk_level = 'Medium'
            elif data['score'] < 150: score_obj.risk_level = 'High'
            else: score_obj.risk_level = 'Critical'

            # Tendência
            if data['score'] > old_score: score_obj.trend = 'Up'
            elif data['score'] < old_score: score_obj.trend = 'Down'
            else: score_obj.trend = 'Stable'
            
            score_obj.save()

            # Eventos Detalhados (Limpa e recria para a janela)
            score_obj.events.filter(timestamp__gte=start_date).delete()
            for ev in data['events']:
                RiskEvent.objects.create(
                    user_risk_score=score_obj,
                    event_source=ev['source'],
                    weight_added=ev['weight'],
                    description=ev['desc'],
                    timestamp=ev['ts']
                )
            results.append(score_obj)

        logger.info(f"Score de Risco atualizado para {len(results)} usuários corporativos.")
        return results

    @staticmethod
    def calculate_score(username, days=7):
        """
        Fallback para cálculo individual (pode ser usado via API se necessário).
        Internamente chama a lógica de agregação ou pode ser mantido simplificado.
        """
        # Para simplificar e manter compatibilidade, vamos apenas disparar o update_all 
        # (já que ele é rápido agora) ou implementar a lógica individual se performance pontual for necessária.
        # Por enquanto, mantemos a assinatura mas recomendamos usar update_all_users.
        start_date = timezone.now() - timedelta(days=days)
        score_obj, created = UserRiskScore.objects.get_or_create(username=username)
        # (Lógica individual simplificada aqui se necessário)
        return score_obj

class MetricsService:
    @staticmethod
    def consolidate_all(days=30):
        """Consolida métricas de todos os módulos."""
        from dashboard.models import DashboardMetric
        
        # Iterar pelos últimos N dias
        for i in range(days + 1):
            target_date = (timezone.now() - timedelta(days=i)).date()
            
            # 1. WebFilter
            MetricsService.consolidate_webfilter(target_date)
            
            # 2. IPS
            MetricsService.consolidate_ips(target_date)
            
            # 3. Antivirus
            MetricsService.consolidate_antivirus(target_date)
            
            # 4. App Control
            MetricsService.consolidate_appcontrol(target_date)
            
            # 5. VPN
            MetricsService.consolidate_vpn(target_date)

        logger.info(f"Consolidação de métricas concluída para os últimos {days} dias.")

    @staticmethod
    def consolidate_webfilter(date):
        from dashboard.models import DashboardMetric
        from security_events.models import SecurityEvent
        from django.db.models import Count, Sum, F
        from django.db.models.functions import Coalesce
        
        # Base QuerySet
        qs = SecurityEvent.objects.filter(event_type='webfilter', date=date)
        
        # Volume Calculation Helper (Bytes In + Bytes Out)
        volume_expr = Coalesce(F('bytes_in'), 0) + Coalesce(F('bytes_out'), 0)
        
        # 1. Total Volume (All actions)
        total_vol = qs.aggregate(v=Sum(volume_expr))['v'] or 0
        DashboardMetric.objects.update_or_create(
            date=date, group='webfilter', metric_name='total_volume', key='all',
            defaults={'volume': total_vol, 'count': qs.count()}
        )
        
        # 2. Blocked Volume
        blocked_qs = qs.filter(action__in=['block', 'blocked'])
        blocked_vol = blocked_qs.aggregate(v=Sum(volume_expr))['v'] or 0
        DashboardMetric.objects.update_or_create(
            date=date, group='webfilter', metric_name='blocked_volume', key='all',
            defaults={'volume': blocked_vol, 'count': blocked_qs.count()}
        )

        # 3. Allowed Volume
        allowed_qs = qs.filter(action__in=['pass', 'allowed', 'passthrough'])
        allowed_vol = allowed_qs.aggregate(v=Sum(volume_expr))['v'] or 0
        DashboardMetric.objects.update_or_create(
            date=date, group='webfilter', metric_name='allowed_volume', key='all',
            defaults={'volume': allowed_vol, 'count': allowed_qs.count()}
        )
        
        # 4. Top Categories (by Blocked Volume - Limit 10)
        top_cats = blocked_qs.values('category').annotate(v=Sum(volume_expr)).order_by('-v')[:10]
        for item in top_cats:
            DashboardMetric.objects.update_or_create(
                date=date, group='webfilter', metric_name='top_categories_volume', key=item['category'] or 'Unknown',
                defaults={'volume': item['v']}
            )

        # 5. Top Sites (by Blocked Volume - Limit 20)
        top_sites = blocked_qs.values('hostname').annotate(v=Sum(volume_expr)).order_by('-v')[:20]
        for item in top_sites:
            # Fallback for sites that might not have a hostname parsed yet
            host_key = item['hostname'] if item['hostname'] else 'Unknown'
            DashboardMetric.objects.update_or_create(
                date=date, group='webfilter', metric_name='top_sites_volume', key=host_key,
                defaults={'volume': item['v']}
            )

        # 6. Top Users (by Blocked Volume - Limit 20)
        top_users = blocked_qs.values('username').annotate(v=Sum(volume_expr)).order_by('-v')[:20]
        for item in top_users:
            DashboardMetric.objects.update_or_create(
                date=date, group='webfilter', metric_name='top_users_volume', key=item['username'] or 'Unknown',
                defaults={'volume': item['v']}
            )

    @staticmethod
    def consolidate_ips(date):
        from dashboard.models import DashboardMetric
        from security_events.models import SecurityEvent
        from django.db.models import Count
        
        qs = SecurityEvent.objects.filter(event_type='ips', date=date)
        
        # Severity summary - Using order_by() to clear default Meta ordering for SQL Server
        sevs = qs.values('severity').annotate(c=Count('id')).order_by()
        for item in sevs:
            DashboardMetric.objects.update_or_create(
                date=date, group='ips', metric_name='severity_dist', key=item['severity'],
                defaults={'count': item['c']}
            )
            
        # Total
        total = sum(item['c'] for item in sevs)
        DashboardMetric.objects.update_or_create(
            date=date, group='ips', metric_name='total_events', key='all',
            defaults={'count': total}
        )

        # Top Attacks
        top_a = qs.exclude(attack_name='').values('attack_name').annotate(c=Count('id')).order_by('-c')[:20]
        for item in top_a:
            DashboardMetric.objects.update_or_create(
                date=date, group='ips', metric_name='top_attacks', key=item['attack_name'],
                defaults={'count': item['c']}
            )

        # Top Sources
        top_s = qs.exclude(src_ip='').values('src_ip').annotate(c=Count('id')).order_by('-c')[:20]
        for item in top_s:
            DashboardMetric.objects.update_or_create(
                date=date, group='ips', metric_name='top_sources', key=item['src_ip'],
                defaults={'count': item['c']}
            )

    @staticmethod
    def consolidate_antivirus(date):
        from dashboard.models import DashboardMetric
        from security_events.models import SecurityEvent
        from django.db.models import Count
        
        qs = SecurityEvent.objects.filter(event_type='antivirus', date=date)
        
        total = qs.count()
        DashboardMetric.objects.update_or_create(
            date=date, group='antivirus', metric_name='total_events', key='all',
            defaults={'count': total}
        )
        
        # Top viruses - Using order_by('-c') which is valid
        top_v = qs.values('virus_name').annotate(c=Count('id')).order_by('-c')[:10]
        for item in top_v:
            DashboardMetric.objects.update_or_create(
                date=date, group='antivirus', metric_name='top_viruses', key=item['virus_name'] or 'Unknown',
                defaults={'count': item['c']}
            )

        # Top Users
        top_u = qs.exclude(username='').values('username').annotate(c=Count('id')).order_by('-c')[:20]
        for item in top_u:
            DashboardMetric.objects.update_or_create(
                date=date, group='antivirus', metric_name='top_users', key=item['username'],
                defaults={'count': item['c']}
            )

    @staticmethod
    def consolidate_appcontrol(date):
        from dashboard.models import DashboardMetric
        from security_events.models import SecurityEvent
        from django.db.models.functions import Coalesce
        from django.db.models import Sum, F
        
        qs = SecurityEvent.objects.filter(event_type='app-control', date=date)
        
        total = qs.count()
        DashboardMetric.objects.update_or_create(
            date=date, group='app-control', metric_name='total_events', key='all',
            defaults={'count': total}
        )
        
        # Top users by volume - order_by('-v') is explicit
        top_u = qs.exclude(username='').values('username').annotate(
            v=Sum(Coalesce(F('bytes_in'), 0) + Coalesce(F('bytes_out'), 0))
        ).order_by('-v')[:15]
        
        for item in top_u:
            DashboardMetric.objects.update_or_create(
                date=date, group='app-control', metric_name='top_users_volume', key=item['username'],
                defaults={'volume': item['v']}
            )

        # Top Apps
        top_a = qs.exclude(app_name='').values('app_name').annotate(c=Count('id')).order_by('-c')[:15]
        for item in top_a:
            DashboardMetric.objects.update_or_create(
                date=date, group='app-control', metric_name='top_apps', key=item['app_name'],
                defaults={'count': item['c']}
            )

        # Top Categories
        top_c = qs.exclude(app_category='').values('app_category').annotate(c=Count('id')).order_by('-c')[:15]
        for item in top_c:
            DashboardMetric.objects.update_or_create(
                date=date, group='app-control', metric_name='top_categories', key=item['app_category'],
                defaults={'count': item['c']}
            )

    @staticmethod
    def consolidate_vpn(date):
        from dashboard.models import DashboardMetric
        from vpn_logs.models import VPNLog
        from django.db.models import Sum, F
        
        qs = VPNLog.objects.filter(start_date=date)
        
        # Total Connections
        total = qs.count()
        DashboardMetric.objects.update_or_create(
            date=date, group='vpn', metric_name='total_connections', key='all',
            defaults={'count': total}
        )
        
        # Total Volume
        vol = qs.aggregate(v=Sum(F('bandwidth_in') + F('bandwidth_out')))['v'] or 0
        DashboardMetric.objects.update_or_create(
            date=date, group='vpn', metric_name='total_volume', key='all',
            defaults={'volume': vol}
        )
        
        # Suspicious
        susp = qs.filter(is_suspicious=True).count()
        DashboardMetric.objects.update_or_create(
            date=date, group='vpn', metric_name='suspicious_connections', key='all',
            defaults={'count': susp}
        )
