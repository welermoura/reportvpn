import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'setup.settings')
django.setup()

from dashboard.models import PortalModule

def populate():
    print("Populating Portal Modules...")
    
    # Clear existing modules to reset state
    PortalModule.objects.all().delete()
    
    modules = [
        {
            'title': 'Report VPN',
            'slug': 'report-vpn',
            'icon': '📊',
            'description': 'Histórico detalhado de conexões, volume de dados e auditoria de acessos.',
            'url_name': 'dashboard:vpn_reports',
            'order': 1
        },
        {
            'title': 'Intrusion Prevention (IPS)',
            'slug': 'ips',
            'icon': '🛡️',
            'description': 'Monitoramento de tentativas de intrusão e ataques bloqueados.',
            'url_name': 'security_events:ips',
            'order': 2
        },
        {
            'title': 'Antivírus / Malware',
            'slug': 'antivirus',
            'icon': '🦠',
            'description': 'Detecção e bloqueio de arquivos maliciosos e vírus.',
            'url_name': 'security_events:antivirus',
            'order': 3
        },
        {
            'title': 'Filtro de Conteúdo Web',
            'slug': 'webfilter',
            'icon': '🚫',
            'description': 'Controle de acesso a sites e categorias bloqueadas.',
            'url_name': 'security_events:webfilter',
            'order': 4
        },
        {
            'title': 'Configurações',
            'slug': 'settings',
            'icon': '⚙️',
            'description': 'Gerenciamento de integrações e parâmetros do sistema.',
            'url_name': 'admin:index',
            'order': 5
        }
    ]
    
    for mod_data in modules:
        m = PortalModule.objects.create(**mod_data)
        print(f"Created module: {m.title}")

if __name__ == '__main__':
    populate()
