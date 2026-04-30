import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from dashboard.models import PortalModule

mod_data = {
    'title': 'FortiGate Feeds',
    'slug': 'fortigate-feeds',
    'icon': 'fa-solid fa-list-check',
    'description': 'Gerenciamento de listas de bloqueio/liberação externas para o FortiGate.',
    'url_name': 'dashboard:fortigate_feeds',
    'order': 9,
    'is_active': True,
    'color': 'text-teal-500'
}

module, created = PortalModule.objects.get_or_create(
    slug=mod_data['slug'],
    defaults=mod_data
)
if not created:
    for key, value in mod_data.items():
        setattr(module, key, value)
    module.save()

print(f"Módulo '{module.title}' {'criado' if created else 'atualizado'} com sucesso!")
