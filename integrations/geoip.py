import requests
import logging
from django.conf import settings

logger = logging.getLogger(__name__)

class GeoIPClient:
    """
    Cliente para consultar geolocalização de IPs.
    Usa ip-api.com (versão free: 45 req/min).
    """
    BASE_URL = "http://ip-api.com/json/"

    def __init__(self):
        self.session = requests.Session()
        self.cache = {}

    def get_location(self, ip_address):
        """
        Retorna dicionário com cidade e país para o IP informado.
        Ex: {'city': 'Sao Paulo', 'country': 'Brazil', 'countryCode': 'BR'}
        """
        if not ip_address or ip_address in ['0.0.0.0', '127.0.0.1', '::1']:
            return None

        # Verificar cache local simples
        if ip_address in self.cache:
            return self.cache[ip_address]

        try:
            # ip-api.com suporta batch, mas vamos fazer 1 a 1 por enquanto com controle
            url = f"{self.BASE_URL}{ip_address}"
            response = self.session.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    result = {
                        'city': data.get('city'),
                        'country_name': data.get('country'),
                        'country_code': data.get('countryCode')
                    }
                    self.cache[ip_address] = result
                    return result
            
            if response.status_code == 429:
                logger.warning(f"GeoIP Rate Limit excedido para {ip_address}")
                
        except Exception as e:
            logger.error(f"Erro ao consultar GeoIP para {ip_address}: {e}")
            
        return None
