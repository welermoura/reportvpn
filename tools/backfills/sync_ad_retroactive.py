import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from vpn_logs.models import VPNLog
from integrations.ad import ActiveDirectoryClient

def sync_ad_retroactive():
    ad = ActiveDirectoryClient()
    # Pega logs que não tem departamento
    logs = VPNLog.objects.filter(ad_department__isnull=True) | VPNLog.objects.filter(ad_department='')
    
    print(f"Encontrados {logs.count()} registros para atualizar.")
    
    updated = 0
    for log in logs:
        if not log.user or log.user.lower() == 'unknown':
            continue
            
        clean_user = log.user.split('\\')[-1]
        print(f"Sincronizando: {clean_user}...", end=' ')
        
        info = ad.get_user_info(clean_user)
        if info:
            log.ad_department = info.get('department')
            log.ad_title = info.get('title')
            log.ad_display_name = info.get('display_name')
            log.ad_email = info.get('email')
            log.save()
            updated += 1
            print("OK")
        else:
            print("Não encontrado no AD")
            
    print(f"Processo finalizado. {updated} registros atualizados.")

if __name__ == "__main__":
    sync_ad_retroactive()
