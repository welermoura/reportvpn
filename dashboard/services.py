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
                ).exclude(travel_details__isnull=True).order_by('-start_time').first()
                
                desc = f"VPN: {item['impossible']} alertas de viagem impossível"
                if last_travel and last_travel.travel_details:
                    prev = last_travel.travel_details.get('previous', {})
                    curr = last_travel.travel_details.get('current', {})
                    hours = last_travel.travel_details.get('time_diff_hours', '?')
                    desc = f"Viagem Impossível: De {prev.get('city') or '?'}/{prev.get('code')} para {curr.get('city') or '?'}/{curr.get('code')} em {hours}h"

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
