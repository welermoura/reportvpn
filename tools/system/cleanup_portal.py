import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from dashboard.models import PortalModule

try:
    module = PortalModule.objects.get(slug='devices')
    module.delete()
    print("Módulo 'devices' removido com sucesso!")
except PortalModule.DoesNotExist:
    print("Módulo 'devices' já não existia no banco de dados.")
except Exception as e:
    print(f"Erro ao remover módulo: {e}")
