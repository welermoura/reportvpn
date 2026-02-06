
import os
import django
from django.conf import settings
import sys


# Setup Django environment
sys.path.append('c:/Users/welerms/Projeto-teste')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from integrations.fortianalyzer import FortiAnalyzerClient
import json
import time

def run_test():
    print("Iniciando teste de verificação do FortiAnalyzerClient...")
    
    client = FortiAnalyzerClient()
    
    # Check config
    print(f"Config: Host={client.config.host}, Adom={client.config.adom}")
    
    # 1. Start Task
    print("\n1. Iniciando tarefa de log (start_log_task)...")
    tid = client.start_log_task(limit=5)
    
    if tid:
        print(f"Sucesso! TID obtido: {tid}")
    else:
        print("Falha ao obter TID.")
        return

    # 2. Get Results (Wait simple delay just in case, though user didn't specify)
    print("\n2. Buscando resultados (get_task_results)...")
    # Tentar algumas vezes caso o FA precise de tempo para processar
    for i in range(3):
        results = client.get_task_results(tid, limit=5)
        if results and 'result' in results:
             data = results['result'].get('data', [])
             if data:
                 print(f"Sucesso! {len(data)} logs retornados.")
                 print("Exemplo de log:")
                 print(json.dumps(data[0], indent=2))
                 break
             else:
                 print(f"Tentativa {i+1}: Nenhum dado ainda (status: {results.get('result', {}).get('status')})...")
                 time.sleep(2)
        else:
            print(f"Erro ao buscar resultados: {results}")
            break

if __name__ == "__main__":
    run_test()
