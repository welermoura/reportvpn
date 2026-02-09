import os
import sys
import django
from django.db.models import DateField
from django.db.models.functions import Cast

# Setup Django environment
sys.path.append('/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from vpn_logs.models import VPNLog

def run():
    print("Starting backfill of start_date...")
    
    total_missing = VPNLog.objects.filter(start_date__isnull=True).count()
    print(f"Found {total_missing} records without start_date.")
    
    if total_missing == 0:
        print("Nothing to update.")
        return

    updated_count = VPNLog.objects.filter(start_date__isnull=True).update(start_date=Cast('start_time', DateField()))
    
    print(f"Successfully updated {updated_count} records.")

if __name__ == '__main__':
    run()
