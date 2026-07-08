import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vpn_dashboard.settings")
django.setup()

from integrations.models import KnownDevice

print("Clearing FWMTZ03 memory alarm...")
d = KnownDevice.objects.filter(hostname='FWMTZ03').first()
if d:
    d.memory_status = 'normal'
    d.last_alert_message = ''
    d.last_alert_time = None
    d.save()
    print("Fixed FWMTZ03!")
else:
    print("FWMTZ03 not found.")
