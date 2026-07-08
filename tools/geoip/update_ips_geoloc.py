"""
Script para retroalimentar os eventos IPS existentes no banco
com os dados de País/Cidade que já estão no raw_log do FortiGate.
"""
import os
import django
import ast

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "core.settings")
django.setup()

from security_events.models import SecurityEvent
from django.db import transaction

def update_ips_geoloc():
    print("🌍 Atualizando dados de País/Cidade para eventos IPS...")
    
    # Buscar eventos IPS que não têm src_country definido
    qs = SecurityEvent.objects.filter(event_type='ips').filter(src_country='')
    total = qs.count()
    all_ips = SecurityEvent.objects.filter(event_type='ips').count()
    
    print(f"   Total IPS no banco: {all_ips}")
    print(f"   Sem src_country: {total}")
    
    updated = 0
    errors = 0
    batch = []
    BATCH_SIZE = 500
    
    for i, event in enumerate(qs.iterator(chunk_size=500)):
        try:
            raw = ast.literal_eval(event.raw_log)
            
            src_country = str(raw.get('srccountry', '')).strip()
            src_city = str(raw.get('srccity', '')).strip()
            dst_country = str(raw.get('dstcountry', '')).strip()
            
            changed = False
            
            if src_country and src_country.lower() not in ['reserved', 'n/a', '']:
                event.src_country = src_country
                changed = True
            
            if dst_country and dst_country.lower() not in ['reserved', 'n/a', '']:
                event.dst_country = dst_country
                changed = True
            
            if changed:
                batch.append(event)
                updated += 1
            
        except Exception as e:
            errors += 1
        
        if len(batch) >= BATCH_SIZE:
            with transaction.atomic():
                SecurityEvent.objects.bulk_update(batch, ['src_country', 'dst_country'])
            print(f"   💾 Gravados {updated} até agora...")
            batch = []
    
    # Gravar restantes
    if batch:
        with transaction.atomic():
            SecurityEvent.objects.bulk_update(batch, ['src_country', 'dst_country'])
    
    print(f"\n✅ Concluído!")
    print(f"   Atualizados: {updated}")
    print(f"   Erros: {errors}")
    
    # Verificar resultado
    sem_pais = SecurityEvent.objects.filter(event_type='ips', src_country='').count()
    com_pais = SecurityEvent.objects.filter(event_type='ips').exclude(src_country='').count()
    print(f"   Com país: {com_pais}")
    print(f"   Ainda sem país: {sem_pais}")

if __name__ == "__main__":
    update_ips_geoloc()
