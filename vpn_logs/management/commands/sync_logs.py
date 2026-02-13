import logging
import datetime
from django.core.management.base import BaseCommand
from django.utils.timezone import make_aware
from django.utils.dateparse import parse_datetime
from integrations.fortianalyzer import FortiAnalyzerClient
from integrations.ad import ActiveDirectoryClient
from vpn_logs.models import VPNLog

logger = logging.getLogger(__name__)

class Command(BaseCommand):
    help = 'Sincroniza logs de VPN do FortiAnalyzer e enriquece com dados do AD'

    def handle(self, *args, **options):
        self.stdout.write("Iniciando sincronização de logs...")
        
        fa_client = FortiAnalyzerClient()
        ad_client = ActiveDirectoryClient()
        
        # Obter logs (exemplo: últimos 100)
        # Em produção, usaríamos timestamps para buscar delta
        try:
            response = fa_client.get_logs(limit=100)
        except Exception as e:
            self.stderr.write(f"Erro ao conectar no FortiAnalyzer: {e}")
            return

        if not response:
            self.stdout.write("Nenhum dado retornado ou erro na conexão.")
            return

        # Parsing da resposta do FA (Ajustar conforme estrutura real do JSON RPC)
        # Assumindo structure: {'result': [{'data': [...]}]} ou direto se o client ja tratasse
        # O client atual retorna response.json() cru.
        
        logs = []
        if 'result' in response and len(response['result']) > 0:
             # Depende da query, as vezes está em result[0]['data']
             result_item = response['result'][0]
             if 'data' in result_item:
                 logs = result_item['data']
        
        if not logs:
            self.stdout.write("Nenhum log encontrado na resposta.")
            # Fallback para debug se a estrutura for diferente
            # self.stdout.write(str(response))
            return

        count_created = 0
        count_updated = 0

        for log_entry in logs:
            session_id = log_entry.get('sessionid') or log_entry.get('logid') # Adapte conforme campo real
            
            if not session_id:
                continue

            user = log_entry.get('user')
            if not user:
                continue

            # Extração de campos básicos
            # FA retorna tempo em strings ou timestamps, precisa converter
            # Exemplo dummy, ajustar parsing
            
            # Tenta buscar objeto existente
            vpn_log, created = VPNLog.objects.get_or_create(
                session_id=session_id,
                defaults={
                    'user': user,
                    'source_ip': log_entry.get('srcip', '0.0.0.0'),
                    'start_time': make_aware(datetime.datetime.now()), # Placeholder se não tiver data
                    'raw_data': log_entry
                }
            )

            # Se já existe ou acabou de criar, vamos atualizar/enriquecer
            # Se a sessão fechou, atualizar end_time, duration, bandwidth
            
            # Enriquecimento com AD
            # Otimização: Poderíamos fazer cache local de usuários para não bater no AD a cada log
            ad_info = ad_client.get_user_info(user)
            if ad_info:
                if vpn_log.ad_department != ad_info.get('department'):
                    vpn_log.ad_department = ad_info.get('department')
                    vpn_log.ad_email = ad_info.get('email')
                    
            # Atualizar outros campos se vierem no log
            if 'duration' in log_entry:
                vpn_log.duration = int(log_entry['duration'])
            
            if 'rcvdbyte' in log_entry:
                vpn_log.bandwidth_in = int(log_entry['rcvdbyte'])
                
            if 'sentbyte' in log_entry:
                vpn_log.bandwidth_out = int(log_entry['sentbyte'])

            if 'status' in log_entry:
                vpn_log.status = log_entry['status']
                
            vpn_log.save()
            
            if created:
                count_created += 1
            else:
                count_updated += 1

        self.stdout.write(self.style.SUCCESS(f"Sincronização concluída. Criados: {count_created}, Atualizados: {count_updated}"))
