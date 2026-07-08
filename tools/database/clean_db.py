import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vpn_dashboard.settings")
django.setup()

from integrations.models import KnownDevice

print("Listing all devices in ALARME status:")
devices = KnownDevice.objects.filter(link_status='alarme')
print(f"Total in alarme: {devices.count()}")

for d in devices:
    print(f"Device {d.hostname} - {d.device_id} - {d.last_alert_message}")
    if d.last_alert_message and "up" in d.last_alert_message.lower():
        d.last_alert_message = ''
    d.link_status = 'normal'
    d.save()

print("Cleaned!")
