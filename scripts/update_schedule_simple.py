import os
import sys
import django

# Setup Django Environment
sys.path.append('/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from django_celery_beat.models import PeriodicTask, IntervalSchedule

def update_schedule():
    print("Starting Celery Schedule Update (Simple)...")
    
    # 1. Create/Get Interval (10 minutes)
    schedule_10min, created = IntervalSchedule.objects.get_or_create(
        every=600,
        period=IntervalSchedule.SECONDS,
    )
    print(f"Interval (600s): {schedule_10min} (Created: {created})")

    # 2. Map of tasks to sync
    # Key: PeriodicTask Name (Display Name via Admin)
    # Value: Registered Task Name (defined in @shared_task(name=...))
    tasks_to_sync = {
        'Coleta de Logs VPN (10 min)': 'Coleta de Logs VPN',
        'Coleta de Eventos IPS (10 min)': 'Coleta de Eventos IPS',
        'Coleta de Eventos Antivirus (10 min)': 'Coleta de Eventos Antivirus',
        'Coleta de Eventos Web Filter (10 min)': 'Coleta de Eventos Web Filter',
    }

    # 3. Create or Update Tasks
    for name, task_path in tasks_to_sync.items():
        task, created = PeriodicTask.objects.update_or_create(
            name=name,
            defaults={
                'task': task_path,
                'interval': schedule_10min,
                'enabled': True,
                'description': 'Automatically created by update_schedule_simple.py'
            }
        )
        status = "Created" if created else "Updated"
        print(f"Task '{name}': {status}")

    # 4. Disable old Bundle Tasks and English Tasks
    old_tasks = [
        'fetch-security-events-every-30-minutes',
        'fetch-vpn-logs-every-10-minutes',
        'fetch-ips-every-10-minutes',
        'fetch-antivirus-every-10-minutes',
        'fetch-webfilter-every-10-minutes'
    ]
    
    for old_name in old_tasks:
        try:
            old_task = PeriodicTask.objects.get(name=old_name)
            old_task.enabled = False
            old_task.save()
            print(f"Old task '{old_name}': Disabled")
        except PeriodicTask.DoesNotExist:
            print(f"Old task '{old_name}': Not found (Clean)")

    print("Update Complete.")

update_schedule()
