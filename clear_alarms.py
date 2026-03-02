import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from integrations.models import KnownDevice

print("Cleaning up old 'Link UP' alerts from the database...")

devices = KnownDevice.objects.filter(last_alert_message__icontains="Link UP")
count = devices.count()
devices.update(last_alert_message='', link_status='normal', last_alert_time=None)

print(f"Cleaned {count} devices.")
