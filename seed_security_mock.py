import os
import django
import random
from django.utils import timezone
from datetime import timedelta

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from security_events.models import SecurityEvent

def create_mock_security_events():
    types = ['ips', 'antivirus', 'webfilter']
    severities = ['critical', 'high', 'medium', 'low']
    countries = ['BR', 'US', 'DE', 'CN', 'RU']
    
    # Limpar antigos
    SecurityEvent.objects.filter(event_id__startswith='mock-').delete()
    print('Cleaned up old mock events')
    
    for i in range(100):
        t = random.choice(types)
        s = random.choice(severities)
        c = random.choice(countries)
        ts = timezone.now() - timedelta(days=random.randint(0, 15), hours=random.randint(0, 23))
        
        SecurityEvent.objects.create(
            event_id=f'mock-{i}-{random.randint(1000,9999)}',
            event_type=t,
            severity=s,
            timestamp=ts,
            date=ts.date(),
            src_ip=f'10.0.0.{random.randint(1,254)}',
            dst_ip=f'172.16.0.{random.randint(1,254)}',
            src_country=c,
            attack_name='Test Exploit Signature' if t == 'ips' else '',
            virus_name='EICAR-Test-File' if t == 'antivirus' else '',
            url='http://blocked-site.com/malicious' if t == 'webfilter' else '',
            action='blocked',
            username=random.choice(['admin', 'user1', 'pedro.oliveira', 'maria.silva'])
        )
    
    print('100 mock security events created successfully!')

if __name__ == '__main__':
    create_mock_security_events()
