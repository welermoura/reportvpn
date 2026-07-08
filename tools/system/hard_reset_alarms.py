import os
import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "vpn_dashboard.settings")
django.setup()

from integrations.models import KnownDevice
from django.core.cache import cache

print("Iniciando limpeza pesada de todos os alarmes dos dispositivos...")

devices = KnownDevice.objects.all()
count = 0

for d in devices:
    d.cpu_status = 'normal'
    d.memory_status = 'normal'
    d.link_status = 'normal'
    d.conserve_mode = False
    d.last_alert_message = ''
    d.last_alert_time = None
    d.save()
    count += 1
    
    # Limpa interface descoberta dinamicamente (Redes)
    import redis
    # The syslog connects to redis on host 'redis' port 6379 db 2. Let's try django cache if configured, 
    # but run_syslog connects raw.
    pass

try:
    import redis
    r = redis.Redis(host='redis', port=6379, db=2)
    keys = r.keys('device_interfaces_*')
    if keys:
        r.delete(*keys)
        print(f"Limpou {len(keys)} chaves de cache (portas descobertas) no Redis.")
except Exception as e:
    print(f"Aviso no Redis: {e}")

print(f"Limpeza de Alarmes concluída em {count} dispositivos no Banco de Dados.")
