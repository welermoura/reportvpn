import os
import django
import urllib.parse

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from vpn_logs.models import VPNLog

def repair_geoip():
    # Pega logs sem país definido
    logs = VPNLog.objects.filter(country_name='') | VPNLog.objects.filter(country_name__isnull=True)
    print(f"Reparando GeoIP para {logs.count()} logs...")
    
    count = 0
    for log in logs:
        raw = log.raw_data
        if not raw:
            continue
            
        # Tenta extrair do log bruto guardado pelo coletor
        country = urllib.parse.unquote(str(raw.get('remcountry', raw.get('srccountry', '')))).strip()
        city = urllib.parse.unquote(str(raw.get('remcity', raw.get('srccity', '')))).strip()
        
        if country and country.lower() not in ['reserved', 'n/a']:
            log.country_name = country
            log.city = city if city.lower() not in ['reserved', 'n/a'] else ''
            
            # Tentar mapear código do país (simplificado)
            COUNTRY_MAP = {'brazil': 'BR', 'united states': 'US', 'argentina': 'AR', 'mexico': 'MX'}
            log.country_code = COUNTRY_MAP.get(country.lower(), '')
            
            log.save()
            count += 1
            print(f"Atualizado {log.user}: {country} - {city}")

    print(f"Reparo finalizado. {count} registros atualizados.")

if __name__ == "__main__":
    repair_geoip()
