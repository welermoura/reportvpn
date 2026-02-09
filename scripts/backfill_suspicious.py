import os
import sys
import django

# Setup Django environment
sys.path.append('/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from vpn_logs.models import VPNLog
from integrations.models import FortiAnalyzerConfig

def run():
    print("Starting backfill of is_suspicious...")
    
    try:
        config = FortiAnalyzerConfig.load()
        trusted_countries = [c.strip().upper() for c in config.trusted_countries.split(',')]
    except Exception as e:
        print(f"Error loading config: {e}")
        trusted_countries = []
        
    print(f"Trusted countries: {trusted_countries}")

    # Mark all as not suspicious first (default)
    # Then mark suspicious ones
    
    # Batch update is faster
    # 1. Update everything to False (default)
    # VPNLog.objects.all().update(is_suspicious=False) # Optional if default is False
    
    # 2. Update suspicious ones
    # suspicious = country_code IS NOT NULL AND country_code NOT IN trusted
    
    total_suspicious = VPNLog.objects.exclude(country_code__in=trusted_countries).exclude(country_code__isnull=True).update(is_suspicious=True)
    
    # Also ensure trusted ones are False (in case of re-run with changed config)
    total_trusted = VPNLog.objects.filter(country_code__in=trusted_countries).update(is_suspicious=False)
    
    print(f"Updated {total_suspicious} records as SUSPICIOUS.")
    print(f"Updated {total_trusted} records as TRUSTED.")

if __name__ == '__main__':
    run()
