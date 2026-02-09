import sys
import os

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import django

# Setup Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from vpn_logs.models import VPNLog

def cleanup():
    count, _ = VPNLog.objects.filter(user='validation_user').delete()
    print(f"Removidos {count} registros de validation_user.")

if __name__ == '__main__':
    cleanup()
