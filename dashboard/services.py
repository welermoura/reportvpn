from django.utils import timezone
from datetime import timedelta
from django.db import models
from security_events.models import SecurityEvent
from vpn_logs.models import VPNLog, VPNFailure
from .models import UserRiskScore, RiskEvent

class RiskScoringService:
    @staticmethod
    def calculate_score(username, days=7):
        """
        Calcula o score de risco do usuário com base nos eventos dos últimos 'days' dias.
        """
        start_date = timezone.now() - timedelta(days=days)
        
        score_data, created = UserRiskScore.objects.get_or_create(username=username)
        old_score = score_data.current_score
        
        total_score = 0
        risk_events = []

        # 1. Eventos de IPS
        ips_events = SecurityEvent.objects.filter(
            username=username, 
            event_type='ips', 
            timestamp__gte=start_date
        )
        for event in ips_events:
            weight = 0
            if event.severity == 'critical': weight = 25
            elif event.severity == 'high': weight = 15
            
            if weight > 0:
                total_score += weight
                risk_events.append({
                    'source': 'ips',
                    'id': event.event_id,
                    'weight': weight,
                    'desc': f"IPS: {event.attack_name} ({event.severity})",
                    'ts': event.timestamp
                })

        # 2. Antivírus
        av_events = SecurityEvent.objects.filter(
            username=username, 
            event_type='antivirus', 
            timestamp__gte=start_date
        )
        for event in av_events:
            total_score += 30
            risk_events.append({
                'source': 'antivirus',
                'id': event.event_id,
                'weight': 30,
                'desc': f"AV: Vírus {event.virus_name} detectado no arquivo {event.file_name}",
                'ts': event.timestamp
            })

        # 3. Web Filter (Bloqueios)
        web_events = SecurityEvent.objects.filter(
            username=username, 
            event_type='webfilter', 
            action='blocked',
            timestamp__gte=start_date
        )
        web_events_count = web_events.count()
        if web_events_count > 0:
            # Reduzir peso de 5 para 2 e limitar a 100 pontos
            weight = min(web_events_count * 2, 100)
            
            # Pegar categorias mais bloqueadas para a descrição
            top_categories = list(web_events.values('category').annotate(count=models.Count('id')).order_by('-count')[:3])
            cat_desc = ", ".join([f"{c['category']} ({c['count']})" for c in top_categories])
            
            total_score += weight
            risk_events.append({
                'source': 'webfilter',
                'weight': weight,
                'desc': f"Web Filter: {web_events_count} bloqueios (Capado em 100 pts). Principais: {cat_desc}",
                'ts': timezone.now()
            })

        # 4. VPN: Acessos Suspeitos ou Viagem Impossível
        vpn_logs = VPNLog.objects.filter(
            user=username,
            start_time__gte=start_date
        )
        for log in vpn_logs:
            if log.is_suspicious:
                total_score += 20
                risk_events.append({
                    'source': 'vpn',
                    'weight': 20,
                    'desc': f"VPN: Acesso de país não confiável ({log.country_name})",
                    'ts': log.start_time
                })
            if log.impossible_travel:
                total_score += 40
                risk_events.append({
                    'source': 'vpn',
                    'weight': 40,
                    'desc': "VPN: Alerta de viagem impossível entre conexões",
                    'ts': log.start_time
                })

        # 5. Falhas de Login VPN (Brute Force)
        failures_count = VPNFailure.objects.filter(
            user=username,
            timestamp__gte=start_date
        ).count()
        if failures_count >= 10:
            total_score += 15
            risk_events.append({
                'source': 'vpn',
                'weight': 15,
                'desc': f"VPN: {failures_count} falhas de login detectadas",
                'ts': timezone.now()
            })

        # Atualizar a pontuação atual
        score_data.current_score = total_score
        
        # Definir nível de risco
        if total_score == 0: score_data.risk_level = 'None'
        elif total_score < 30: score_data.risk_level = 'Low'
        elif total_score < 70: score_data.risk_level = 'Medium'
        elif total_score < 150: score_data.risk_level = 'High'
        else: score_data.risk_level = 'Critical'

        # Calcular tendência
        if total_score > old_score: score_data.trend = 'Up'
        elif total_score < old_score: score_data.trend = 'Down'
        else: score_data.trend = 'Stable'
        
        score_data.save()

        # Limpar eventos antigos da janela e registrar novos
        score_data.events.filter(timestamp__gte=start_date).delete()
        for re in risk_events:
            RiskEvent.objects.create(
                user_risk_score=score_data,
                event_source=re['source'],
                event_id=re.get('id', ''),
                weight_added=re['weight'],
                description=re['desc'],
                timestamp=re['ts']
            )
            
        return score_data

    @classmethod
    def update_all_users(cls, days=7):
        """
        Gera o score de risco para todos os usuários que tiveram atividade recente.
        """
        # Obter todos os usernames únicos de todas as fontes
        usernames = set()
        usernames.update(SecurityEvent.objects.values_list('username', flat=True))
        usernames.update(VPNLog.objects.values_list('user', flat=True))
        usernames.update(VPNFailure.objects.values_list('user', flat=True))
        
        results = []
        for username in usernames:
            if username: # Ignorar usernames vazios
                results.append(cls.calculate_score(username, days))
        
        return results
