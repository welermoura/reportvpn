import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from security_events.models import SecurityEvent

def debug_log():
    # Busca o log mais recente que cita internal3 ou wan2
    log = SecurityEvent.objects.filter(raw_log__icontains='internal3').order_by('-timestamp').first()
    if log:
        print("LOG ENCONTRADO:")
        print(log.raw_log)
        data = json.loads(log.raw_log)
        for k, v in data.items():
            print(f"  {k}: {v}")
    else:
        print("Nenhum log de internal3 encontrado.")

if __name__ == "__main__":
    debug_log()
