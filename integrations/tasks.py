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
    
    import time
    
    try:
        # 1. VPN Logs (Chunked Deletes)
        vpn_del = 0
        while True:
            old_vpn_ids = list(VPNLog.objects.filter(start_time__lt=cutoff_date).values_list('id', flat=True)[:5000])
            if not old_vpn_ids:
                break
            deleted, _ = VPNLog.objects.filter(id__in=old_vpn_ids).delete()
            vpn_del += deleted
            time.sleep(0.1)
        
        # 2. VPN Failures (Chunked Deletes)
        vpnf_del = 0
        while True:
            old_vpnf_ids = list(VPNFailure.objects.filter(timestamp__lt=cutoff_date).values_list('id', flat=True)[:5000])
            if not old_vpnf_ids:
                break
            deleted, _ = VPNFailure.objects.filter(id__in=old_vpnf_ids).delete()
            vpnf_del += deleted
            time.sleep(0.1)
        
        # 3. Security Events (Chunked Deletes)
        sec_del = 0
        while True:
            old_sec_ids = list(SecurityEvent.objects.filter(timestamp__lt=cutoff_date).values_list('id', flat=True)[:5000])
            if not old_sec_ids:
                break
            deleted, _ = SecurityEvent.objects.filter(id__in=old_sec_ids).delete()
            sec_del += deleted
            time.sleep(0.1)
        
        # 4. AD Auth Events (Chunked Deletes)
        ad_del = 0
        while True:
            old_ad_ids = list(ADAuthEvent.objects.filter(timestamp__lt=cutoff_date).values_list('id', flat=True)[:5000])
            if not old_ad_ids:
                break
            deleted, _ = ADAuthEvent.objects.filter(id__in=old_ad_ids).delete()
            ad_del += deleted
            time.sleep(0.1)
        
        # 5. Dashboard Metrics (DashboardMetric)
        # IMPORTANTE: Preservamos os dados consolidados do DashboardMetric para que o histórico
        # dos dashboards visuais nunca seja perdido, em conformidade com as exigências do usuário.
        dash_del = 0
        
        total = vpn_del + vpnf_del + sec_del + ad_del
        msg = (f"Limpeza de logs finalizada com segurança (Deleção em lotes de 5000). "
               f"Removidos: {vpn_del} VPNLogs, {vpnf_del} VPNFailures, "
               f"{sec_del} SecurityEvents, {ad_del} ADAuthEvents. "
               f"DashboardMetric preservado: {dash_del} deletados. Total de logs limpos: {total}")
        logger.info(msg)
        return msg
        
    except Exception as e:
        logger.error(f"Erro durante a limpeza de logs: {e}")
        return f"Erro: {str(e)}"
