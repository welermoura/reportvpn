import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from dashboard.models import PortalModule

modules = [
    {
        'title': 'Acessos VPN',
        'slug': 'vpn-logs',
        'icon': 'fa-solid fa-network-wired',
        'description': 'Acesso aos logs de conexão da VPN.',
        'url_name': 'dashboard:vpn_reports',
        'order': 1,
        'is_active': True
    },
    {
        'title': 'Intrusão (IPS)',
        'slug': 'ips-events',
        'icon': 'fa-solid fa-shield-halved',
        'description': 'Painel de Eventos de Intrusão (IPS).',
        'url_name': 'security_events:ips',
        'order': 2,
        'is_active': True
    },
    {
        'title': 'Antivírus',
        'slug': 'antivirus-events',
        'icon': 'fa-solid fa-virus',
        'description': 'Painel de Eventos de Antivírus.',
        'url_name': 'security_events:antivirus',
        'order': 3,
        'is_active': True
    },
    {
        'title': 'Web Filter',
        'slug': 'webfilter-events',
        'icon': 'fa-solid fa-globe',
        'description': 'Painel de Eventos de Web Filter.',
        'url_name': 'security_events:webfilter',
        'order': 4,
        'is_active': True
    },
    {
        'title': 'Força Bruta',
        'slug': 'bruteforce-events',
        'icon': 'fa-solid fa-user-lock',
        'description': 'Painel de Eventos de Falhas de Autenticação (Força Bruta).',
        'url_name': 'dashboard:bruteforce_dashboard',
        'order': 5,
        'is_active': True
    },
    {
        'title': 'Score de Risco',
        'slug': 'risk-scores',
        'icon': 'fa-solid fa-chart-line',
        'description': 'Análise de Score de Risco de Usuários.',
        'url_name': 'dashboard:risk_dashboard',
        'order': 6,
        'is_active': True
    }
]

print("Iniciando a inserção dos módulos do portal...")
for mod_data in modules:
    module, created = PortalModule.objects.get_or_create(
        slug=mod_data['slug'],
        defaults=mod_data
    )
    if not created:
        for key, value in mod_data.items():
            setattr(module, key, value)
        module.save()
    print(f"Módulo '{module.title}' {'criado' if created else 'atualizado'}.")

print("Todos os módulos foram inseridos com sucesso!")
