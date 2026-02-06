import os
import django
from django.conf import settings

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from integrations.geoip import GeoIPClient

def test_geoip():
    client = GeoIPClient()
    
    # Test Google DNS IP
    TEST_IP = '8.8.8.8'
    print(f"Testando GeoIP para {TEST_IP}...")
    
    result = client.get_location(TEST_IP)
    
    if result:
        print("Sucesso!")
        print(f"País: {result.get('country_name')} ({result.get('country_code')})")
        print(f"Cidade: {result.get('city')}")
    else:
        print("Falha ao obter localização. Verifique logs ou conexão.")

if __name__ == '__main__':
    test_geoip()
