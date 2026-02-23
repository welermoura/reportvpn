import requests
from django.conf import settings
from .models import FortiAnalyzerConfig

class FortiAnalyzerClient:
    def __init__(self):
        self.config = FortiAnalyzerConfig.load()
        if self.config.api_token:
            self.config.api_token = self.config.api_token.strip()
            
    def get_session(self):
        session = requests.Session()
        session.verify = self.config.verify_ssl
        session.headers.update({
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.config.api_token}'
        })
        return session

    def start_log_task(self, log_type="event", start_time=None, end_time=None, limit=100, log_filter=None):
        """
        Inicia uma tarefa de busca de logs no FortiAnalyzer (Log View API v3).
        Retorna o TID (Task ID) se bem sucedido.
        """
        if not self.config.host:
            raise ValueError("Host do FortiAnalyzer não configurado.")

        url = f"{self.config.host}:{self.config.port}/jsonrpc"
        
        # Filtro de tempo padrão se não informado (últimas 24h)
        import datetime
        import pytz
        
        # FortiAnalyzer opera em horário local (BRT -03:00).
        # O Django/Celery rodam em UTC no container.
        # Precisamos converter os timestamps para BRT antes de enviar.
        brt = pytz.timezone('America/Sao_Paulo')
        now_utc = datetime.datetime.now(datetime.timezone.utc)
        now_local = now_utc.astimezone(brt)
        
        s = start_time if start_time else (now_local - datetime.timedelta(days=1))
        e = end_time if end_time else now_local
        
        # Converter start_time e end_time para BRT se tiver tzinfo
        if hasattr(s, 'tzinfo') and s.tzinfo is not None:
            s = s.astimezone(brt)
        if hasattr(e, 'tzinfo') and e.tzinfo is not None:
            e = e.astimezone(brt)
        
        # Formatar datas: "YYYY-MM-DDTHH:MM:SS" no fuso do FA (BRT)
        time_range = {
            "start": s.strftime("%Y-%m-%dT%H:%M:%S"),
            "end": e.strftime("%Y-%m-%dT%H:%M:%S")
        }

        # Filtro padrão se não informado
        if not log_filter:
            # Incluir falhas: action in ('tunnel-up', 'tunnel-down', 'negotiate-error', 'auth-failure', 'ssl-login-fail')
            # Sintaxe do FortiAnalyzer: (action=="tunnel-up" or action=="negotiate-error" ...)
            log_filter = 'subtype=="vpn"'

        payload = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "add",
            "params": [
                {
                    "apiver": 3,
                    "url": f"/logview/adom/{self.config.adom}/logsearch",
                    "logtype": log_type,
                    "time-order": "desc",
                    "time-range": time_range,
                    "filter": log_filter
                }
            ]
        }
        
        try:
            session = self.get_session()
            response = session.post(url, json=payload, timeout=10)
            response.raise_for_status()
            result = response.json()
            
            # Analisar resposta para pegar o TID
            # Esperado: { "jsonrpc": "2.0", "result": { "tid": 2069823706 }, "id": 1 }
            if 'result' in result:
                res_data = result['result']
                if isinstance(res_data, dict) and 'tid' in res_data:
                    return res_data['tid']
                elif isinstance(res_data, list) and len(res_data) > 0 and 'tid' in res_data[0]:
                    return res_data[0]['tid']
                
            print(f"Aviso: Não foi possível obter TID na resposta: {result}")
            return None

        except requests.RequestException as e:
            print(f"Erro ao iniciar tarefa no FA: {e}")
            return None

    def check_task_status(self, tid):
        """
        Verifica o status de uma tarefa pelo TID.
        """
        if not tid:
            return None
            
        url = f"{self.config.host}:{self.config.port}/jsonrpc"
        payload = {
            "id": 1,
            "jsonrpc": "2.0",
            "method": "get",
            "params": [
                {
                    "url": f"/logview/adom/{self.config.adom}/task/{tid}" 
                }
            ]
        }
        
        try:
            session = self.get_session()
            response = session.post(url, json=payload, timeout=5)
            result = response.json()
            
            # Parse result for status
            if 'result' in result:
                res_data = result['result']
                # Pode ser lista
                if isinstance(res_data, list) and len(res_data) > 0:
                    return res_data[0]
                elif isinstance(res_data, dict):
                    return res_data
            
            return None
        except Exception as e:
             print(f"Erro ao checar status da task {tid}: {e}")
             return None

    def get_task_results(self, tid, limit=100, offset=0):
        """
        Baixa os resultados de uma tarefa concluída dado o TID.
        """
        if not tid:
            return None

        url = f"{self.config.host}:{self.config.port}/jsonrpc"
        payload = {
            "id": 2,
            "jsonrpc": "2.0",
            "method": "get",
            "params": [
                {
                    "apiver": 3,
                    "url": f"/logview/adom/{self.config.adom}/logsearch/{tid}",
                    "data": { "limit": limit, "offset": offset }
                }
            ]
        }
        
        try:
            session = self.get_session()
            response = session.post(url, json=payload, timeout=30)
            return response.json()
        except Exception as e:
            print(f"Erro ao baixar resultados da task {tid}: {e}")
            return None
