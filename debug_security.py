import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from security_events.models import SecurityEvent
from django.db.models import Min, Max, Count
from collections import Counter

total = SecurityEvent.objects.count()
print(f"Total Security Events: {total}")

# Date range
agg = SecurityEvent.objects.aggregate(min_d=Min('date'), max_d=Max('date'))
print(f"Date range: {agg['min_d']} to {agg['max_d']}")

# Types
types = dict(SecurityEvent.objects.values('event_type').annotate(c=Count('id')).order_by().values_list('event_type', 'c'))
print(f"Types: {types}")

# Sample events
print("\n--- Sample events ---")
for e in SecurityEvent.objects.all()[:5]:
    print(f"  ID={e.id} type={e.event_type} sev={e.severity} date={e.date} src={e.src_ip} event_id={e.event_id[:50]}")

# Check if event_id looks like mock data
print("\n--- Event ID pattern check ---")
sample_ids = list(SecurityEvent.objects.values_list('event_id', flat=True)[:3])
for eid in sample_ids:
    print(f"  {eid}")
