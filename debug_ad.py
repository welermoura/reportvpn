import os
import django
import sys

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from integrations.ad import ActiveDirectoryClient
from security_events.models import SecurityEvent

def test_ad_lookup(username):
    print(f"\n--- Testing AD Lookup for: {username} ---")
    try:
        client = ActiveDirectoryClient()
        info = client.get_user_info(username)
        print(f"Result: {info}")
    except Exception as e:
        print(f"Error: {e}")

def check_db_stats():
    print("\n--- Database Stats ---")
    total = SecurityEvent.objects.count()
    with_display_name = SecurityEvent.objects.exclude(ad_display_name='').count()
    without_display_name = SecurityEvent.objects.filter(ad_display_name='').count()
    
    print(f"Total SecurityEvents: {total}")
    print(f"With ad_display_name: {with_display_name}")
    print(f"Without ad_display_name: {without_display_name}")
    
    # Show sample of missing
    if without_display_name > 0:
        sample = SecurityEvent.objects.filter(ad_display_name='').values_list('username', flat=True).distinct()[:5]
        print(f"Sample usernames without display name: {list(sample)}")

if __name__ == "__main__":
    check_db_stats()
    test_ad_lookup("ALESSANDROJVS")
    test_ad_lookup("daniloc")
