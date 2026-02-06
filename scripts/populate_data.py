import os
import django
from django.utils import timezone
import random
from datetime import timedelta

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from vpn_logs.models import VPNLog

def create_dummy_data():
    users = ['alice.smith', 'bob.jones', 'charlie.brown', 'david.wilson', 'eve.davis']
    departments = ['IT', 'HR', 'Sales', 'Engineering', 'Marketing']
    
    print("Criando dados fictícios...")
    
    for i in range(50):
        user = random.choice(users)
        dept = random.choice(departments)
        start = timezone.now() - timedelta(days=random.randint(0, 30), hours=random.randint(0, 23))
        duration = random.randint(300, 28800) # 5 min a 8 horas
        
        VPNLog.objects.create(
            session_id=f'sess-{i}-{random.randint(1000,9999)}',
            user=user,
            source_ip=f'192.168.1.{random.randint(1, 254)}',
            start_time=start,
            end_time=start + timedelta(seconds=duration),
            duration=duration,
            bandwidth_in=random.randint(1000000, 100000000),
            bandwidth_out=random.randint(500000, 50000000),
            status='tunnel-down',
            ad_department=dept,
            ad_email=f'{user}@example.com',
            raw_data={'dummy': True}
        )
    
    print("50 logs criados com sucesso!")

if __name__ == '__main__':
    create_dummy_data()
