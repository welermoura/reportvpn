import django, os
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from django.conf import settings
db = settings.DATABASES['default']
print(f"ENGINE: {db['ENGINE']}")
print(f"HOST: {db.get('HOST', 'N/A')}")
print(f"PORT: {db.get('PORT', 'N/A')}")
print(f"NAME: {db.get('NAME', 'N/A')}")

from vpn_logs.models import VPNLog
print(f"\nVPNLog count (web): {VPNLog.objects.count()}")

# Try to create a test log and see if it persists
from django.utils import timezone
import datetime

test_log = VPNLog(
    session_id='test-debug-001',
    user='debug_test',
    source_ip='1.2.3.4',
    start_time=timezone.now(),
    start_date=timezone.now().date(),
    duration=100,
    bandwidth_in=1000,
    bandwidth_out=2000,
    status='closed'
)
test_log.bypass_suspicious_check = True
test_log.save()
print(f"Test log saved with ID: {test_log.id}")
print(f"VPNLog count after save: {VPNLog.objects.count()}")

# Clean up
VPNLog.objects.filter(session_id='test-debug-001').delete()
print(f"VPNLog count after delete: {VPNLog.objects.count()}")
