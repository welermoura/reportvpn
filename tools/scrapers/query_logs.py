import sys
import os
import django

# Setup Django
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from vpn_logs.models import VPNLog
from django.utils import timezone

logs = VPNLog.objects.filter(user__icontains='rafaelasamc').order_by('-start_time')[:5]

print("--- RECENT LOGS FOR RAFAELASAMC ---")
for log in logs:
    print(f"ID: {log.id}")
    print(f"Start: {log.start_time}")
    print(f"End: {log.end_time}")
    print(f"Duration (seconds): {log.duration}")
    print(f"Formatted Duration: {log.formatted_duration()}")
    print("Raw FA Duration:", log.raw_data.get('duration'))
    print("Raw FA Action:", log.raw_data.get('action'))
    print("Raw FA Status:", log.status)
    print("-" * 30)
