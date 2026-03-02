from celery import shared_task
from django.utils import timezone
from datetime import timedelta
import logging

logger = logging.getLogger(__name__)

@shared_task(name='integrations.tasks.cleanup_old_logs')
def cleanup_old_logs():
    """
    Deleta registros de logs mais antigos que o período de retenção configurado.
    """
    from setup.models import DatabaseConfiguration
    from vpn_logs.models import VPNLog, VPNFailure
    from security_events.models import SecurityEvent, ADAuthEvent
    from dashboard.models import DashboardMetric
    
    config = DatabaseConfiguration.get_active_config()
    
    if not config or not config.is_retention_enabled:
        logger.info("Limpeza automática de logs ignorada: configuração desativada ou não encontrada.")
        return "Desativado"
        
    days = config.retention_days
    if days <= 0:
        logger.info("Retenção configurada como 0 (infinito). Nenhuma limpeza executada.")
        return "Infinito"
        
    cutoff_date = timezone.now() - timedelta(days=days)
    logger.info(f"Iniciando limpeza de logs anteriores a {cutoff_date} ({days} dias).")
    
    try:
        # VPN
        vpn_del, _ = VPNLog.objects.filter(start_time__lt=cutoff_date).delete()
        vpnf_del, _ = VPNFailure.objects.filter(timestamp__lt=cutoff_date).delete()
        
        # Security
        sec_del, _ = SecurityEvent.objects.filter(timestamp__lt=cutoff_date).delete()
        ad_del, _ = ADAuthEvent.objects.filter(timestamp__lt=cutoff_date).delete()
        
        # Dashboard Summary
        dash_del, _ = DashboardMetric.objects.filter(date__lt=cutoff_date.date()).delete()
        
        total = vpn_del + vpnf_del + sec_del + ad_del + dash_del
        msg = (f"Limpeza concluída. Removidos: {vpn_del} VPNLogs, {vpnf_del} VPNFailures, "
               f"{sec_del} SecurityEvents, {ad_del} ADAuthEvents, {dash_del} Metrics. Total: {total}")
        logger.info(msg)
        return msg
        
    except Exception as e:
        logger.error(f"Erro durante a limpeza de logs: {e}")
        return f"Erro: {str(e)}"
