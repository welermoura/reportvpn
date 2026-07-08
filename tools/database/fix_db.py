import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from django_celery_beat.models import PeriodicTask

# Fix the task name
tasks = PeriodicTask.objects.filter(name='Coleta de Eventos (IPS/AV/Web/AppControl)')
for t in tasks:
    t.task = 'security_events.tasks.fetch_security_events_task'
    t.save()
    print("Updated task:", t.name)
    
# Also update the old one if it exists
old_tasks = PeriodicTask.objects.filter(name='Coleta de Eventos de Segurança (30 min)')
for t in old_tasks:
    t.name = 'Coleta de Eventos (IPS/AV/Web/AppControl)'
    t.task = 'security_events.tasks.fetch_security_events_task'
    t.description = 'Coleta automática de eventos (IPS, AV, Web Filter, App Control) do FortiAnalyzer a cada 30 minutos'
    t.save()
    print("Updated old task:", t.name)
