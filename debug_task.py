import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger('vpn_logs.tasks')
logger.setLevel(logging.DEBUG)

# Clear any existing lock
from django.core.cache import cache
cache.delete("fetch_vpn_logs_lock")

print("=== Running fetch_vpn_logs_task directly ===")
from vpn_logs.tasks import fetch_vpn_logs_task
result = fetch_vpn_logs_task()
print(f"\nResult: {result}")

from vpn_logs.models import VPNLog
print(f"VPNLog count after task: {VPNLog.objects.count()}")
for log in VPNLog.objects.all()[:5]:
    print(f"  {log.id}: user={log.user}, date={log.start_date}, ip={log.source_ip}")
