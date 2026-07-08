from celery import shared_task
from .services import RiskScoringService
import logging

logger = logging.getLogger(__name__)


@shared_task(
    bind=True,
    name='Atualizar Scores de Risco',
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=300,
    max_retries=3,
)
def update_user_risk_scores_task(self):
    logger.info("Iniciando atualização de scores de risco...")
    results = RiskScoringService.update_all_users(days=7)
    logger.info(f"Atualização concluída para {len(results)} usuários.")
    return f"Updated {len(results)} users"


@shared_task(
    bind=True,
    name='Consolidar Metricas Dashboard',
    autoretry_for=(Exception,),
    retry_backoff=True,
    retry_backoff_max=300,
    max_retries=3,
)
def consolidate_metrics_task(self, days=1):
    from .services import MetricsService
    logger.info("Iniciando consolidação de métricas...")
    MetricsService.consolidate_all(days=days)
    return f"Consolidation for {days} days completed"
