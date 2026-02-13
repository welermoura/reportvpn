
import sys
import os
import django

# Add project root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from django.conf import settings
from django_celery_beat.models import PeriodicTask, IntervalSchedule

# Setup Django if run standalone (though we'll use manage.py shell)
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

def update_schedule():
    print("Starting Celery Schedule Update...")
    
    # 1. Create/Get Interval (10 minutes)
    schedule_10min, created = IntervalSchedule.objects.get_or_create(
        every=600,
        period=IntervalSchedule.SECONDS,
    )
    print(f"Interval (600s): {schedule_10min} (Created: {created})")

    # 2. Map of tasks to sync
    # Name in DB -> Task Function Path
    tasks_to_sync = {
        'fetch-vpn-logs-every-10-minutes': 'vpn_logs.tasks.fetch_vpn_logs_task',
        'fetch-ips-every-10-minutes': 'security_events.tasks.fetch_ips_task',
        'fetch-antivirus-every-10-minutes': 'security_events.tasks.fetch_antivirus_task',
        'fetch-webfilter-every-10-minutes': 'security_events.tasks.fetch_webfilter_task',
    }

    # 3. Create or Update Tasks
    for name, task_path in tasks_to_sync.items():
        task, created = PeriodicTask.objects.update_or_create(
            name=name,
            defaults={
                'task': task_path,
                'interval': schedule_10min,
                'enabled': True,
                'description': 'Automatically created by update_celery_schedule.py'
            }
        )
        status = "Created" if created else "Updated"
        print(f"Task '{name}': {status}")

    # 4. Disable/Delete old Bundle Task if exists
    old_task_name = 'fetch-security-events-every-30-minutes'
    try:
        old_task = PeriodicTask.objects.get(name=old_task_name)
        old_task.enabled = False
        old_task.save()
        print(f"Old task '{old_task_name}': Disabled")
        # old_task.delete() # Optional: delete if you want to clean up
    except PeriodicTask.DoesNotExist:
        print(f"Old task '{old_task_name}': Not found (Clean)")

    print("Update Complete. DatabaseScheduler should pick up changes shortly.")

if __name__ == '__main__':
    update_schedule()
