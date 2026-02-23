import os
import django
import sys

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from security_events.models import SecurityEvent
from security_events.tasks import fetch_security_events_task

def reimport_appcontrol():
    print("🧹 Deletando logs vazios do AppControl anteriores...")
    deleted, _ = SecurityEvent.objects.filter(event_type='app-control').delete()
    print(f"Deletados: {deleted} eventos.")
    
    print("📥 Coletando eventos (App Control) a partir da engine de tráfego do FA...")
    resultado = fetch_security_events_task('app-control')
    print("Resultado do script:")
    print(resultado)

if __name__ == "__main__":
    reimport_appcontrol()
