import os
import django
import sys
import time

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from integrations.ad import ActiveDirectoryClient
from security_events.models import SecurityEvent

def populate_ad_data():
    print("Iniciando populacao de dados do AD...")
    
    # Get unique usernames that are missing display_name
    events_to_update = SecurityEvent.objects.filter(ad_display_name='').exclude(username='')
    unique_usernames = events_to_update.values_list('username', flat=True).distinct()
    
    print(f"Encontrados {events_to_update.count()} eventos para atualizar.")
    print(f"Total de {len(unique_usernames)} usuarios unicos para consultar.")
    
    ad_client = ActiveDirectoryClient()
    
    user_cache = {}
    
    for username in unique_usernames:
        if not username:
            continue
            
        print(f"Consultando AD para: {username}...")
        try:
            info = ad_client.get_user_info(username)
            if info:
                user_cache[username] = info
                # Handle potential None values here or during update
                dname = info.get('display_name')
                print(f"  -> Encontrado: {dname}")
            else:
                print(f"  -> Nao encontrado no AD.")
                user_cache[username] = None 
        except Exception as e:
            print(f"  -> Erro: {e}")
            
    # Now update events
    print("Atualizando eventos no banco de dados...")
    count = 0
    updated_users = 0
    
    for username, info in user_cache.items():
        if info:
            # Safely get values, handling None
            display_name = (info.get('display_name') or '')[:255]
            title = (info.get('title') or '')[:255]
            department = (info.get('department') or '')[:255]
            email = (info.get('email') or '')
            
            # Update all events for this user
            rows = SecurityEvent.objects.filter(username=username, ad_display_name='').update(
                ad_display_name=display_name,
                ad_title=title,
                user_department=department,
                user_email=email
            )
            count += rows
            updated_users += 1
            print(f"Atualizado {rows} eventos para usuario {username}")
            
    print("------------------------------------------------")
    print(f"Concluido! Total de eventos atualizados: {count}")
    print(f"Total de usuarios com dados encontrados: {updated_users}")

if __name__ == "__main__":
    populate_ad_data()
