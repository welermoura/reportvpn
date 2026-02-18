from celery import shared_task
from .services import RiskScoringService
import logging

logger = logging.getLogger(__name__)

@shared_task(name='Atualizar Scores de Risco')
def update_user_risk_scores_task():
    """
    Recalcula o score de risco para todos os usuários com atividade recente.
    """
    try:
        logger.info("Iniciando atualização de scores de risco...")
        results = RiskScoringService.update_all_users(days=7)
        logger.info(f"Atualização concluída para {len(results)} usuários.")
        return f"Updated {len(results)} users"
    except Exception as e:
        logger.error(f"Erro ao atualizar scores de risco: {e}")
        return f"Error: {e}"
