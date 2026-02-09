from django.core.management.base import BaseCommand
from vpn_logs.tasks import fetch_vpn_logs_task

class Command(BaseCommand):
    help = 'Dispara a tarefa de coleta de logs via Celery'

    def handle(self, *args, **options):
        self.stdout.write('Disparando tarefa fetch_vpn_logs_task no Celery...')
        task = fetch_vpn_logs_task.delay()
        self.stdout.write(self.style.SUCCESS(f'Tarefa agendada com ID: {task.id}'))
