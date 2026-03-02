import os
import django
import json

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dashboard.settings')
django.setup()

from security_events.models import SecurityEvent

print("Buscando logs que contenham a palavra 'alias'...")
events = SecurityEvent.objects.filter(raw_data__icontains='alias').order_by('-timestamp')[:10]

for e in events:
    print("-" * 40)
    print("RAW:", e.raw_data)
    try:
        from log_receiver.parsers.fortinet import parse_fortinet_syslog
        parsed = parse_fortinet_syslog(e.raw_data)
        print("PARSED:", json.dumps(parsed, indent=2))
    except Exception as ex:
        pass
    
print("\nBuscando logs de SD-WAN/Health-Check...")
hc_events = SecurityEvent.objects.filter(raw_data__icontains='health-check').order_by('-timestamp')[:5]
for e in hc_events:
    print("-" * 40)
    print("RAW:", e.raw_data)

print("Finalizado.")
