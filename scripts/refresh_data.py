
import os
import django
import sys

sys.path.append('c:/Users/welerms/Projeto-teste')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from vpn_logs.models import VPNLog
from django.core.management import call_command

print(f"Logs atuais no DB: {VPNLog.objects.count()}")
print("Apagando logs antigos (fictícios)...")
VPNLog.objects.all().delete()
print(f"Logs após limpeza: {VPNLog.objects.count()}")

print("Executando fetch_logs...")
try:
    # Running fetch_logs with the same logic as management command but invoked here
    # or just call_command if safe
    call_command('fetch_logs')
except Exception as e:
    print(f"Erro ao executar fetch_logs: {e}")

print(f"Total Logs finais: {VPNLog.objects.count()}")
if VPNLog.objects.exists():
    print("Último log:", VPNLog.objects.first().user, VPNLog.objects.first().start_time)
