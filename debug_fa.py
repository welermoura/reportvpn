import os
import django
import sys
import json

# Configurar Django
sys.path.append('/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from integrations.fortianalyzer import FortiAnalyzerClient
import datetime
from django.utils import timezone

def test_fa_filters():
    client = FortiAnalyzerClient()
    start_date = timezone.now() - datetime.timedelta(days=365)
    
    filters = [
        'subtype=="vpn" and tunneltype=="ssl-tunnel"',
        'subtype=="vpn" and tunneltype=="ssl"',
        'subtype=="vpn" and tunneltype=="ipsec"'
    ]
    
    for f in filters:
        print(f"\nTestando filtro: {f}")
        try:
            tid = client.start_log_task(start_time=start_date, limit=10, log_filter=f)
            if not tid:
                print("Falha ao iniciar task.")
                continue
                
            print(f"Task iniciada. TID: {tid}. Aguardando 10s...")
            import time
            time.sleep(10)
            
            results = client.get_task_results(tid, limit=10)
            data = []
            if 'result' in results:
                res = results['result']
                if isinstance(res, dict):
                    data = res.get('data', [])
                elif isinstance(res, list) and len(res) > 0:
                    data = res[0].get('data', [])
            
            print(f"Registros encontrados para {f}: {len(data)}")
            if data:
                print(f"Ação do primeiro: {data[0].get('action')}")
        except Exception as e:
            print(f"Erro: {e}")

if __name__ == "__main__":
    test_fa_filters()
