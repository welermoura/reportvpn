
import os
import django
import sys
import json
import datetime
from django.utils import timezone

sys.path.append('c:/Users/welerms/Projeto-teste')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from integrations.fortianalyzer import FortiAnalyzerClient

def inspect_logs():
    client = FortiAnalyzerClient()
    
    # Filter used in fetch_logs
    filter_str = 'subtype=="vpn" and tunneltype=="ssl"'
    
    # Fetch recent logs to inspect structure
    days_ago = 60
    start_date = timezone.now() - datetime.timedelta(days=days_ago)
    
    # Try a broader filter or just the current one
    # Let's keep the current one to see if ANY SSL log has a user
    filter_str = 'subtype=="vpn" and action=="tunnel-down" and tunneltype=="ssl-tunnel"' 
    
    print(f"Buscando amostra de logs com filtro: {filter_str}")
    # High limit to increase chance of finding a user
    tid = client.start_log_task(start_time=start_date, limit=200, log_filter=filter_str)
    
    if not tid:
        print("Falha ao obter TID")
        return

    print(f"TID: {tid}. Aguardando...")
    import time
    time.sleep(15)
    
    results = client.get_task_results(tid, limit=200)
    
    logs_data = []
    if results and 'result' in results:
        res = results['result']
        if isinstance(res, dict):
            logs_data = res.get('data', [])
        elif isinstance(res, list) and len(res) > 0:
            logs_data = res[0].get('data', [])
            
    print(f"\nEncontrados {len(logs_data)} logs.")
    
    count_with_user = 0
    for i, log in enumerate(logs_data):
        user = log.get('user', 'N/A')
        if user != 'N/A' and user != '':
            print(f"\n--- Log with USER found ({i+1}) ---")
            print(json.dumps(log, indent=2))
            count_with_user += 1
            if count_with_user >= 3: break # Show top 3
            
    if count_with_user == 0:
        print("\nNenhum log com usuário válido encontrado na amostra.")
        # Print one sample N/A log to see action/msg
        if len(logs_data) > 0:
             print("\nExemplo de log SEM usuário:")
             print(json.dumps(logs_data[0], indent=2))

if __name__ == "__main__":
    inspect_logs()
