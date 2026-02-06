from django.core.management.base import BaseCommand
from django.utils import timezone
from dateutil.parser import parse
from integrations.fortianalyzer import FortiAnalyzerClient
from integrations.ad import ActiveDirectoryClient
from integrations.geoip import GeoIPClient
from vpn_logs.models import VPNLog
import datetime

class Command(BaseCommand):
    help = 'Coleta logs de VPN do FortiAnalyzer e enriquece com dados do AD'

    def handle(self, *args, **options):
        self.stdout.write(self.style.SUCCESS('Iniciando coleta de logs...'))

        fa_client = FortiAnalyzerClient()
        ad_client = ActiveDirectoryClient()
        geoip_client = GeoIPClient()

        # Definir janela de tempo (ex: últimos 60 minutos se rodar frequentemente)
        # Para teste inicial, vamos tentar pegar um range fixo ou confiar no limit
        # Idealmente, persistir o último timestamp coletado no DB.
        
        try:
            # Buscar logs - Lógica Assíncrona (TID)
            self.stdout.write('Iniciando tarefa de geração de logs no FortiAnalyzer (Histórico completo - 365 dias)...')
            
            # Buscando logs desde 1 ano atrás
            days_ago = 365
            start_date = timezone.now() - datetime.timedelta(days=days_ago)
            
            # Limite aumentado
            fetch_limit = 10000 
            
            # Filtro específico: Tunnel type "ssl-tunnel" traz logs de conexão (up/down) com usuários
            filter_str = 'subtype=="vpn" and tunneltype=="ssl-tunnel"'
            
            tid = fa_client.start_log_task(start_time=start_date, limit=fetch_limit, log_filter=filter_str)
            
            if not tid:
                self.stdout.write(self.style.ERROR('Falha ao obter TID do FortiAnalyzer. Verifique se o ADOM e configurações estão corretos.'))
                return
                
            self.stdout.write(f"Tarefa iniciada. TID: {tid}. Buscando logs desde {start_date.strftime('%Y-%m-%d')}")
            
            # Aguardar um momento para o FA processar
            self.stdout.write("Aguardando processamento do FortiAnalyzer (15s)...")
            import time
            time.sleep(15) 
            
            # Polling removido temporariamente em favor de wait simples
            task_done = True
            
            self.stdout.write('Baixando resultados...')
            response = fa_client.get_task_results(tid, limit=fetch_limit) # Limitado para teste inicial
            
            if not response:
                self.stdout.write(self.style.WARNING('Nenhum dado retornado ou erro na conexão.'))
                return

            # Análise básica da estrutura da resposta JSON-RPC do FA
            # Geralmente: {'result': [{'data': [...]}]} ou direto se o cliente trata
            
            logs_data = []
            if 'result' in response:
                res = response['result']
                if isinstance(res, dict):
                    logs_data = res.get('data', [])
                elif isinstance(res, list) and len(res) > 0:
                    logs_data = res[0].get('data', [])
            elif isinstance(response, list):
                logs_data = response
            elif 'data' in response:
                logs_data = response['data']
            else:
                self.stdout.write(self.style.WARNING(f'Formato de resposta desconhecido: {str(response)[:200]}'))
                return

            self.stdout.write(f'Encontrados {len(logs_data)} registros brutos.')
            
            count_new = 0
            for log in logs_data:
                # Mapeamento de campos (ajustar conforme os campos reais do seu FA)
                # Log fields example: user, srcip, duration, rcvdbyte, sentbyte, devid, vd, timestamp/date/time
                
                # Identificador único. Se não tiver session_id explícito, criar hash?
                # Vamos tentar usar sessionid ou construir um ID
                session_id = str(log.get('sessionid', ''))
                # Se session_id vazio mas tem tunnelid, usar tunnelid
                if not session_id or session_id == '0':
                    session_id = str(log.get('tunnelid', ''))
                    
                if not session_id or session_id == '0':
                     # Fallback extremo
                     session_id = f"{log.get('date', '')}-{log.get('time', '')}-{log.get('user', '')}"
                
                if VPNLog.objects.filter(session_id=session_id).exists():
                    continue

                username = log.get('user', 'unknown')
                if username == 'N/A':
                    # Tentra xauthuser se disponível
                    username = log.get('xauthuser', 'N/A')

                # Fix for IP: FortiAnalyzer logs often use 'remip' (Remote IP) for VPN
                source_ip = log.get('remip')
                if not source_ip or source_ip == '0.0.0.0':
                    source_ip = log.get('srcip', '0.0.0.0')

                # Calcular timestamps
                try:
                    log_date = log.get('date', '')
                    log_time = log.get('time', '')
                    start_time = parse(f"{log_date} {log_time}")
                    # Tornar timezone aware se necessário
                    if timezone.is_naive(start_time):
                        start_time = timezone.make_aware(start_time)
                except:
                    start_time = timezone.now()

                duration = int(log.get('duration', 0))
                end_time = start_time + datetime.timedelta(seconds=duration)
                
                # Determine status based on action
                action = log.get('action', '')
                status = 'tunnel-down' # Default
                if action == 'tunnel-up':
                    status = 'active'
                elif action == 'tunnel-down':
                    status = 'closed'

                # Busca no AD
                ad_info = {}
                if username and username != 'unknown' and username != 'N/A':
                    # Remover domínio se vier (ex: DOMAIN\user)
                    clean_user = username.split('\\')[-1]
                    ad_info = ad_client.get_user_info(clean_user) or {}

                # Busca GeoIP
                geo_info = {}
                if source_ip and source_ip != '0.0.0.0':
                    geo_info = geoip_client.get_location(source_ip) or {}

                vpn_log = VPNLog(
                    session_id=session_id,
                    user=username,
                    source_ip=source_ip,
                    start_time=start_time,
                    end_time=end_time,
                    duration=duration,
                    bandwidth_in=int(log.get('rcvdbyte', 0)),
                    bandwidth_out=int(log.get('sentbyte', 0)),
                    status=status,
                    raw_data=log,
                    # Dados AD
                    ad_department=ad_info.get('department'),
                    ad_email=ad_info.get('email'),
                    ad_title=ad_info.get('title'),
                    ad_display_name=ad_info.get('display_name'),
                    # Dados GeoIP
                    city=geo_info.get('city'),
                    country_name=geo_info.get('country_name'),
                    country_code=geo_info.get('country_code')
                )
                vpn_log.save()
                count_new += 1
                self.stdout.write(f"Importado: {username} (Dept: {ad_info.get('department')})")

            self.stdout.write(self.style.SUCCESS(f'Processamento concluído. {count_new} novos logs importados.'))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f'Erro durante execução: {e}'))
            import traceback
            traceback.print_exc()
