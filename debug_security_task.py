import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

import logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger('security_events.tasks')
logger.setLevel(logging.DEBUG)

# Clear any existing lock
from django.core.cache import cache
cache.delete("fetch_security_events_lock")

# Check current data before
from security_events.models import SecurityEvent
print(f"=== BEFORE: {SecurityEvent.objects.count()} security events ===")

# Run the task directly
print("\n=== Running fetch_security_events_task directly ===")
from security_events.tasks import fetch_security_events_task
result = fetch_security_events_task()
print(f"\nResult: {result}")

# Check after
total = SecurityEvent.objects.count()
print(f"\n=== AFTER: {total} security events ===")

from django.db.models import Count
types = SecurityEvent.objects.values('event_type').annotate(c=Count('id')).order_by()
for t in types:
    print(f"  {t['event_type']}: {t['c']}")

# Show some newly added events (if any)
from django.db.models import Max
newest = SecurityEvent.objects.order_by('-timestamp')[:3]
for e in newest:
    print(f"  Latest: {e.event_type} | {e.timestamp} | {e.src_ip} | {e.event_id[:40]}")
