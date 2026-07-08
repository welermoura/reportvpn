import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from security_events.models import SecurityEvent

def check_events():
    devid = 'FGT60FTK2109DB7G'
    print(f"Buscando logs de 'event' para {devid}...")
    
    logs = SecurityEvent.objects.filter(
        raw_log__icontains=devid,
        raw_log__icontains='"type": "event"'
    ).order_by('-timestamp')[:20]
    
    print(f"Encontrados {logs.count()} logs.")
    
    for l in logs:
        try:
            data = json.loads(l.raw_log)
            print(f"TS: {l.timestamp} | Sub: {data.get('subtype')} | Desc: {data.get('logdesc')} | Msg: {data.get('msg')}")
        except:
            continue

if __name__ == "__main__":
    check_events()
