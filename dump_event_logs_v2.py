import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from security_events.models import SecurityEvent

def check_events():
    devid = 'FGT60FTK2109DB7G'
    print(f"Buscando últimos 200 logs para {devid}...")
    
    logs = SecurityEvent.objects.filter(raw_log__icontains=devid).order_by('-timestamp')[:200]
    
    found_any_event = False
    for l in logs:
        try:
            data = json.loads(l.raw_log)
            ltype = data.get('type')
            if ltype != 'event': continue
            
            found_any_event = True
            subtype = data.get('subtype')
            desc = data.get('logdesc')
            msg = data.get('msg')
            
            print(f"TS: {l.timestamp} | Sub: {subtype} | Desc: {desc}")
            print(f"  Msg: {msg}")
            print("-" * 30)
        except:
            continue
    
    if not found_any_event:
        print("Nenhum log do tipo 'event' encontrado nos últimos 200 registros.")

if __name__ == "__main__":
    check_events()
