import os
import django
import random
from datetime import timedelta
from django.utils import timezone

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from security_events.models import SecurityEvent

def seed_data():
    print("Gerando dados fictícios de segurança...")
    
    # Limpar dados antigos
    SecurityEvent.objects.all().delete()
    
    ips_attacks = [
        ('SQL Injection Attempt', 'critical', '50102'),
        ('Cross Site Scripting (XSS)', 'high', '40520'),
        ('Brute Force Attack', 'high', '30201'),
        ('Port Scan Detected', 'medium', '10500'),
        ('Anomalous Traffic Flow', 'low', '10100'),
    ]
    
    viruses = [
        ('Worm.Python.Malware.a', 'critical'),
        ('Trojan.Generic.KD.12345', 'critical'),
        ('Adware.Win32.Popuper', 'medium'),
        ('Ransomware.LockBit.v3', 'critical'),
    ]
    
    web_categories = [
        ('Social Networking', 'allowed'),
        ('Gambling', 'blocked'),
        ('Malware Sites', 'blocked'),
        ('Shopping', 'monitored'),
        ('News and Media', 'allowed'),
    ]
    
    users = ['admin', 'joao.silva', 'maria.santos', 'pedro.oliveira', 'ana.costa']
    
    for i in range(100):
        event_type = random.choice(['ips', 'antivirus', 'webfilter'])
        timestamp = timezone.now() - timedelta(hours=random.randint(1, 168))
        
        event = SecurityEvent(
            event_id=f"EVT-{i:05}",
            event_type=event_type,
            timestamp=timestamp,
            date=timestamp.date(),
            src_ip=f"192.168.1.{random.randint(2, 254)}",
            dst_ip=f"10.0.0.{random.randint(2, 254)}",
            src_port=random.randint(1024, 65535),
            dst_port=random.randint(80, 443),
            src_country=random.choice(['Brazil', 'USA', 'China', 'Russia', 'Germany']),
            username=random.choice(users),
            raw_log="Mock raw log data for testing dashboard functionality."
        )
        
        if event_type == 'ips':
            attack = random.choice(ips_attacks)
            event.attack_name = attack[0]
            event.severity = attack[1]
            event.attack_id = attack[2]
        
        elif event_type == 'antivirus':
            virus = random.choice(viruses)
            event.virus_name = virus[0]
            event.severity = virus[1]
            event.file_name = f"document_{i}.docx"
        
        elif event_type == 'webfilter':
            cat = random.choice(web_categories)
            event.category = cat[0]
            event.action = cat[1]
            event.severity = 'medium' if cat[1] == 'blocked' else 'info'
            event.url = f"http://www.{cat[0].lower().replace(' ', '')}.com/path/{i}"
            
        event.save()
        
    print(f"Sucesso! {SecurityEvent.objects.count()} eventos criados.")

if __name__ == "__main__":
    seed_data()
