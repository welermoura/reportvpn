import os
import django
import json

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from security_events.models import SecurityEvent

# Pegar os 20 eventos mais recentes de app-control que tenham raw_log
events = SecurityEvent.objects.filter(event_type='app-control').exclude(raw_log='').order_by('-timestamp')[:20]

print(f"Encontrados {len(events)} eventos recentes.")

all_keys = set()
for e in events:
    try:
        raw = json.loads(e.raw_log)
        all_keys.update(raw.keys())
        # Procurar por qualquer campo que pareça tamanho/bytes
        byte_fields = [k for k in raw.keys() if 'byte' in k.lower() or 'sent' in k.lower() or 'rcvd' in k.lower() or 'size' in k.lower()]
        if byte_fields:
            print(f"Evento {e.id} ({e.app_name}): {[(k, raw[k]) for k in byte_fields]}")
    except:
        pass

print("\nTodas as chaves encontradas nos logs JSON:")
print(sorted(list(all_keys)))
