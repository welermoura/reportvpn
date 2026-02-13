from django.core.management.base import BaseCommand
from vpn_logs.tasks import fetch_vpn_logs_task

class Command(BaseCommand):
    help = 'Dispara a tarefa de coleta de logs via Celery'

    def add_arguments(self, parser):
        parser.add_argument(
            '--sync',
            action='store_true',
            help='Executar de forma síncrona (sem Celery)',
        )

    def handle(self, *args, **options):
        if options['sync']:
            self.stdout.write('Executando fetch_vpn_logs_task de forma síncrona...')
            result = fetch_vpn_logs_task()
            self.stdout.write(self.style.SUCCESS(f'Resultado: {result}'))
        else:
            self.stdout.write('Disparando tarefa fetch_vpn_logs_task no Celery...')
            task = fetch_vpn_logs_task.delay()
            self.stdout.write(self.style.SUCCESS(f'Tarefa agendada com ID: {task.id}'))
