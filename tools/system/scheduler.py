import schedule
import time
import os
import sys
import django
from django.core.management import call_command
from datetime import datetime

# Setup Django Environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

def job_fetch_logs():
    print(f"[{datetime.now()}] Starting fetch_logs...")
    try:
        call_command('fetch_logs')
        print(f"[{datetime.now()}] fetch_logs completed.")
    except Exception as e:
        print(f"[{datetime.now()}] Error in fetch_logs: {e}")

def job_cleanup_logs():
    print(f"[{datetime.now()}] Starting cleanup_logs...")
    try:
        call_command('cleanup_logs')
        print(f"[{datetime.now()}] cleanup_logs completed.")
    except Exception as e:
        print(f"[{datetime.now()}] Error in cleanup_logs: {e}")

# Schedule Configuration
# 1. Fetch logs every 10 minutes
schedule.every(10).minutes.do(job_fetch_logs)

# 2. Cleanup logs daily at 03:00 AM
schedule.every().day.at("03:00").do(job_cleanup_logs)

# 3. Daily Consolidation (Fetch one last time at 23:59)
schedule.every().day.at("23:59").do(job_fetch_logs)

print("Scheduler started...")
print("- Fetch Logs: Every 10 minutes")
print("- Cleanup Logs: Daily at 03:00")
print("- Consolidation: Daily at 23:59")

# Run the first fetch immediately on startup (optional, currently disabled to respect schedule only)
# job_fetch_logs() 

while True:
    schedule.run_pending()
    time.sleep(1)
