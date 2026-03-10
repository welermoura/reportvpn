from datetime import datetime, timedelta
import pytz
import time
from django.core.management.base import BaseCommand
from django.utils import timezone
from integrations.fortianalyzer import FortiAnalyzerClient
from tabulate import tabulate
from vpn_logs.tasks import daily_fidelity_vpn_report_task
from vpn_logs.models import VPNLog

class Command(BaseCommand):
    help = 'Gera e exibe o relatório de fidelidade VPN do dia anterior (persistido no banco)'

    def add_arguments(self, parser):
        parser.add_argument('--date', type=str, help='Data específica (YYYY-MM-DD). Padrão: ontem.')
        parser.add_argument('--force', action='store_true', help='Forçar nova coleta do FortiAnalyzer.')

    def handle(self, *args, **options):
        brt = pytz.timezone('America/Sao_Paulo')
        now_local = datetime.now(brt)
        
        target_date_str = options.get('date')
        if target_date_str:
            try:
                target_date = datetime.strptime(target_date_str, '%Y-%m-%d').date()
            except:
                self.stderr.write(self.style.ERROR("Formato de data inválido. Use YYYY-MM-DD."))
                return
        else:
            target_date = (now_local - timedelta(days=1)).date()

        self.stdout.write(self.style.NOTICE(f"Relatório VPN para o dia: {target_date.strftime('%d/%m/%Y')}"))

        # Se force ou se não houver registros "fidelity" para o dia, executa a coleta
        fidelity_exists = VPNLog.objects.filter(start_date=target_date, session_id__startswith='fidelity_').exists()
        
        if options.get('force') or not fidelity_exists:
            self.stdout.write(self.style.WARNING("Iniciando coleta de fidelidade (D-1) no FortiAnalyzer... Isso pode levar alguns minutos."))
            result = daily_fidelity_vpn_report_task(target_date.isoformat() if target_date_str else None)
            self.stdout.write(self.style.SUCCESS(f"Resultado da Coleta: {result}"))
        else:
            self.stdout.write(self.style.SUCCESS("Carregando dados pré-existentes do banco de dados..."))

        # Buscar dados persistidos (Fidelity Only)
        logs = VPNLog.objects.filter(
            start_date=target_date,
            session_id__startswith='fidelity_'
        ).order_by('-bandwidth_in', '-bandwidth_out')

        if not logs.exists():
            self.stdout.write(self.style.WARNING(f"Nenhum registro de fidelidade encontrado no banco para {target_date}."))
            return

        table_rows = []
        for idx, log in enumerate(logs, 1):
            # Volume total formatado (In + Out já está nos campos individuais)
            # Mas o formatted_volume no model usa bandwidth_in + bandwidth_out se não me engano
            vol_s = log.formatted_volume()
            dur_s = log.formatted_duration()
            
            table_rows.append([
                idx, 
                log.user, 
                "ssl-tunnel", 
                "GRUPOHA", 
                log.start_time.strftime('%Y-%m-%d %H:%M:%S'), 
                log.source_ip, 
                vol_s, 
                log.raw_data.get('conns', 1),
                dur_s
            ])

        headers = ["ID", "User", "VPN Type", "Devices", "Last Conn", "Connected IP", "Connected Bytes", "# of Conne", "Duration"]
        self.stdout.write("\n" + tabulate(table_rows, headers=headers, tablefmt="grid"))
        self.stdout.write("\n" + self.style.SUCCESS(f"Exibindo {len(table_rows)} registros persistidos para {target_date}."))






