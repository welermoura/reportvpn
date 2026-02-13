import os
import django
import sys

# Configurar Django
sys.path.append('/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from django.conf import settings
from vpn_logs.models import VPNLog
from django.contrib.auth.models import User

def check_db():
    print("--- DATABASE CONFIG ---")
    db = settings.DATABASES['default']
    print(f"ENGINE: {db['ENGINE']}")
    print(f"NAME: {db.get('NAME')}")
    print(f"HOST: {db.get('HOST')}")
    print(f"USER: {db.get('USER')}")
    
    print("\n--- DATA CHECK ---")
    print(f"Users in DB: {[u.username for u in User.objects.all()]}")
    print(f"VPN Log Count: {VPNLog.objects.count()}")
    
    if VPNLog.objects.exists():
        sample = VPNLog.objects.order_by('-start_time').first()
        print(f"Sample Log: {sample.user} - {sample.start_time} - {sample.ad_department}")

if __name__ == "__main__":
    check_db()
