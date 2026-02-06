import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from vpn_logs.models import VPNLog

def check():
    total = VPNLog.objects.count()
    with_city = VPNLog.objects.exclude(city__isnull=True).exclude(city__exact='').count()
    with_country = VPNLog.objects.exclude(country_name__isnull=True).exclude(country_name__exact='').count()
    
    print(f"Total Logs: {total}")
    print(f"Logs with City: {with_city}")
    print(f"Logs with Country: {with_country}")
    
    if total > 0:
        last = VPNLog.objects.last()
        print(f"Last Log ID: {last.id}")
        print(f"Last Log IP: {last.source_ip}")
        print(f"Last Log City: '{last.city}'")
        print(f"Last Log Country: '{last.country_name}'")

if __name__ == '__main__':
    check()
