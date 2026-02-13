import os
import django

# Configurar Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from integrations.models import FortiAnalyzerConfig, ActiveDirectoryConfig

def restore_configs():
    print("Restaurando configurações do FortiAnalyzer...")
    fa = FortiAnalyzerConfig.load()
    fa.host = "https://10.10.1.52"
    fa.port = 443
    fa.adom = "root"
    fa.api_token = "g7pswamouf7yjscrgiypioykzcucdq3n"
    fa.verify_ssl = False
    fa.trusted_countries = "BR"
    fa.save()
    print("Configuração do FortiAnalyzer restaurada.")

    print("Restaurando configurações do Active Directory...")
    ad = ActiveDirectoryConfig.load()
    ad.server = "dzmtzdc05.grupocomolatti.corp"
    ad.port = 389
    ad.use_ssl = False
    ad.base_dn = "DC=grupocomolatti,DC=corp"
    ad.bind_user = "grupocomolatti\\contato"
    ad.bind_password = "Cont@to#2025"
    ad.save()
    print("Configuração do Active Directory restaurada.")

if __name__ == "__main__":
    restore_configs()
