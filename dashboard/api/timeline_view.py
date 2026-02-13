from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from django.db.models import Q
from vpn_logs.models import VPNLog
from security_events.models import SecurityEvent
from .serializers import VPNLogSerializer
from security_events.api.serializers import SecurityEventSerializer

class UserTimelineViewSet(viewsets.ViewSet):
    permission_classes = [IsAuthenticated]

    def list(self, request):
        """
        Retorna a timeline unificada para um usuário específico.
        Query param: ?username=welerton.santos
        """
        username = request.query_params.get('username')
        if not username:
            return Response({"error": "Username is required"}, status=400)

        # Buscar Logs de VPN
        vpn_logs = VPNLog.objects.filter(
            Q(user__iexact=username) | Q(ad_display_name__icontains=username)
        ).order_by('-start_time')[:50]

        # Buscar Falhas de Login (Brute Force Analysis)
        from vpn_logs.models import VPNFailure
        vpn_failures = VPNFailure.objects.filter(
            Q(user__iexact=username)
        ).order_by('-timestamp')[:20]

        # Buscar Eventos de Segurança (Todos os tipos)
        security_events = SecurityEvent.objects.filter(
            Q(username__iexact=username) | Q(ad_display_name__icontains=username)
        ).order_by('-timestamp')[:50]

        timeline_data = []

        # Formatar VPN Logs
        for log in vpn_logs:
            timeline_data.append({
                "id": f"vpn_{log.id}",
                "type": "vpn",
                "timestamp": log.start_time,
                "summary": f"Conexão VPN de {log.city or 'Local Desconhecido'}/{log.country_code or ''}",
                "details": {
                    "source_ip": log.source_ip,
                    "duration": log.formatted_duration(),
                    "status": log.status,
                    "impossible_travel": log.impossible_travel,
                    "is_suspicious": log.is_suspicious
                },
                "severity": "critical" if log.impossible_travel else ("medium" if log.is_suspicious else "info")
            })

        # Formatar Falhas de Login
        for failure in vpn_failures:
            timeline_data.append({
                "id": f"fail_{failure.id}",
                "type": "vpn_failure",
                "timestamp": failure.timestamp,
                "summary": f"Falha de Login VPN ({failure.reason or 'Desconhecido'})",
                "details": {
                    "source_ip": failure.source_ip,
                    "location": f"{failure.city or ''}/{failure.country_code or ''}",
                    "reason": failure.reason
                },
                "severity": "warning"
            })

        # Formatar Security Events
        for event in security_events:
            summary = ""
            details = {}
            
            if event.event_type == 'bruteforce':
                summary = "🚨 ATAQUE DE FORÇA BRUTA DETECTADO"
                details = {"attempts": event.details, "action": event.action}
            elif event.event_type == 'ips':
                summary = f"Ataque IPS: {event.attack_name}"
                details = {"attack_id": event.attack_id, "action": event.action}
            elif event.event_type == 'antivirus':
                summary = f"Vírus Detectado: {event.virus_name}"
                details = {"file": event.file_name, "action": event.action}
            elif event.event_type == 'webfilter':
                summary = f"Web Filter: {event.category}"
                details = {"url": event.url, "action": event.action}

            timeline_data.append({
                "id": f"sec_{event.id}",
                "type": "security",
                "subtype": event.event_type,
                "timestamp": event.timestamp,
                "summary": summary,
                "details": details,
                "severity": event.severity
            })

        # Ordenar tudo por data (mais recente primeiro)
        timeline_data.sort(key=lambda x: x['timestamp'], reverse=True)

        return Response(timeline_data)
