import os
import django
import re

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from vpn_logs.models import VPNLog
from vpn_logs.tasks import fetch_vpn_logs_task

midnight_logs = VPNLog.objects.filter(session_id__contains='_midnight_')
print(f"Encontrados {midnight_logs.count()} logs fragmentados (midnight). Restaurando as sessões originais...")

restaurados = 0
for m_log in midnight_logs:
    # O padrão é: originalSession_midnight_DATE_UUID
    # Vamos extrair a originalSession
    parts = m_log.session_id.split('_midnight_')
    if len(parts) == 2:
        original_session_id = parts[0]
        
        # Deleta a "nova" sessão que tomou a session_id original para continuar o contador
        VPNLog.objects.filter(session_id=original_session_id).delete()
        
        # Restaura a sessão original
        m_log.session_id = original_session_id
        m_log.status = 'active' # FA update will close it if needed
        m_log.duration = 0
        m_log.end_time = None
        m_log.save()
        restaurados += 1

print(f"Foram restauradas {restaurados} sessões para seu estado puro.")
print("Rodando a rotina de sincronização (paginada) do FortiAnalyzer para recalcular as durações em definitivo...")
fetch_vpn_logs_task()
print("Restauração e ressincronização concluídas com sucesso!")
