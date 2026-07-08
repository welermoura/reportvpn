import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from dashboard.models import PortalModule

def add_module():
    module, created = PortalModule.objects.get_or_create(
        slug='brute-force',
        defaults={
            'title': 'Monitoramento de Força Bruta',
            'description': 'Painel dedicado a análise de tentativas de falha de login e ataques de força bruta.',
            'icon': 'fas fa-user-lock',
            'url_name': 'dashboard:bruteforce_dashboard',
            'is_active': True,
            'order': 5
        }
    )
    if created:
        print("Módulo 'Força Bruta' criado com sucesso.")
    else:
        print("Módulo 'Força Bruta' já existe.")
        # Ensure it's active and has correct URL
        module.is_active = True
        module.url_name = 'dashboard:bruteforce_dashboard'
        module.save()
        print("Módulo atualizado.")

if __name__ == "__main__":
    add_module()
