import os
import django
import requests
import time

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from vpn_logs.models import VPNLog

def repair_via_api():
    # Pega logs sem país
    logs = VPNLog.objects.filter(country_name='') | VPNLog.objects.filter(country_name__isnull=True)
    print(f"Total para analisar: {logs.count()}")
    
    count = 0
    for log in logs:
        ip = log.source_ip
        # Ignorar IPs privados
        if not ip or ip.startswith('10.') or ip.startswith('172.16.') or ip.startswith('192.168.') or ip == '0.0.0.0':
            continue
            
        print(f"Consultando IP: {ip}...", end=" ")
        try:
            # Usando ip-api (gratuito para demo/pequeno volume)
            r = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            data = r.json()
            
            if data.get('status') == 'success':
                log.country_name = data.get('country')
                log.city = data.get('city')
                log.country_code = data.get('countryCode')
                log.save()
                count += 1
                print(f"OK ({log.country_name})")
            else:
                print(f"Falha API: {data.get('message')}")
                
            # Rate limit preventivo para API gratuita
            time.sleep(1.2)
            
            if count >= 100: # Limite por rodada
                break
                
        except Exception as e:
            print(f"Erro: {e}")
            
    print(f"Fim. {count} registros atualizados.")

if __name__ == "__main__":
    repair_via_api()
