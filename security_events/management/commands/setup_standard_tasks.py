from django.core.management.base import BaseCommand
from django_celery_beat.models import PeriodicTask, IntervalSchedule, CrontabSchedule
import json

class Command(BaseCommand):
    help = 'Setup standard periodic tasks for the application'

    def handle(self, *args, **options):
        self.stdout.write("Setting up standard periodic tasks...")

        # 1. VPN Logs Task (Every 10 minutes)
        schedule_10m, created = IntervalSchedule.objects.get_or_create(
            every=10,
            period=IntervalSchedule.MINUTES,
        )
        
        vpn_task, created = PeriodicTask.objects.get_or_create(
            name='Coleta de Logs VPN (10 min)',
            defaults={
                'task': 'vpn_logs.tasks.fetch_vpn_logs_task',
                'interval': schedule_10m,
                'enabled': True,
                'description': 'Coleta automática de logs de VPN do FortiAnalyzer a cada 10 minutos'
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f"Created task: {vpn_task.name}"))
        else:
            self.stdout.write(f"Task already exists: {vpn_task.name}")

        # 2. Security Events Task (Every 30 minutes)
        schedule_30m, created = IntervalSchedule.objects.get_or_create(
            every=30,
            period=IntervalSchedule.MINUTES,
        )

        sec_task, created = PeriodicTask.objects.get_or_create(
            name='Coleta de Eventos de Segurança (30 min)',
            defaults={
                'task': 'security_events.tasks.fetch_security_events_task',
                'interval': schedule_30m,
                'enabled': True,
                'description': 'Coleta automática de eventos (IPS, AV, Web) do FortiAnalyzer a cada 30 minutos'
            }
        )
        if created:
            self.stdout.write(self.style.SUCCESS(f"Created task: {sec_task.name}"))
        else:
            self.stdout.write(f"Task already exists: {sec_task.name}")

        self.stdout.write(self.style.SUCCESS("Standard tasks setup completed."))
