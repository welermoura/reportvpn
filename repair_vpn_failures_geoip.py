import os
import django
import time
import requests
import json
import redis
import logging

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from vpn_logs.models import VPNFailure

# Setup Redis
try:
    redis_client = redis.Redis(host='redis', port=6379, db=2, decode_responses=True)
except:
    redis_client = None

def get_geoip_data(ip):
    """Reuse the logic from run_syslog.py"""
    if not ip or ip.startswith(('10.', '172.16.', '192.168.', '127.', '0.0.0.0')):
        return {}

    cache_key = f"geoip:{ip}"
    if redis_client:
        cached = redis_client.get(cache_key)
        if cached:
            try:
                return json.loads(cached)
            except:
                pass

    try:
        # Usando ip-api (gratuito para demo)
        r = requests.get(f"http://ip-api.com/json/{ip}", timeout=3)
        data = r.json()
        if data.get('status') == 'success':
            res = {
                'country': data.get('country'),
                'city': data.get('city'),
                'country_code': data.get('countryCode')
            }
            if redis_client:
                redis_client.setex(cache_key, 86400, json.dumps(res)) # 24h cache
            return res
    except Exception as e:
        print(f"GeoIP Error for {ip}: {e}")
    
    return {}

def repair_geoip():
    # Filtrar registros que não têm cidade ou código de país
    queryset = VPNFailure.objects.filter(
        django.db.models.Q(city__isnull=True) | 
        django.db.models.Q(city='') | 
        django.db.models.Q(country_code__isnull=True) | 
        django.db.models.Q(country_code='')
    )
    
    total = queryset.count()
    print(f"Encontrados {total} registros para reparar GeoIP.")
    
    count = 0
    updated = 0
    
    for failure in queryset:
        count += 1
        ip = failure.source_ip
        
        # Ignorar IPs internos óbvios
        if not ip or ip.startswith(('10.', '172.16.', '192.168.', '127.')):
            continue
            
        data = get_geoip_data(ip)
        if data:
            failure.city = data.get('city')
            failure.country_code = data.get('country_code')
            failure.country_name = data.get('country')
            failure.save()
            updated += 1
            
        if count % 10 == 0:
            print(f"Processado: {count}/{total}...")
            
        # Respeitar limite de taxa do ip-api (45 requisições por minuto se não for cacheado)
        # Se veio do cache do Redis, não precisa de sleep.
        # Por segurança, um pequeno delay.
        time.sleep(0.5)

    print(f"Reparação concluída! {updated} registros atualizados.")

if __name__ == "__main__":
    repair_geoip()
