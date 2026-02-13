import os
import django
from django.conf import settings
from rest_framework.test import APIRequestFactory

# Setup Django
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from dashboard.api.timeline_view import UserTimelineViewSet
from vpn_logs.models import VPNLog
from django.contrib.auth.models import User

def verify_timeline():
    # 1. Get a user with logs
    log = VPNLog.objects.first()
    if not log:
        print("No VPN logs found to test with.")
        return

    username = log.user
    print(f"Testing timeline for user: {username}")

    # 2. Simulate API Request
    factory = APIRequestFactory()
    request = factory.get(f'/api/user-timeline/?username={username}')
    
    # Force authentication (mock)
    view = UserTimelineViewSet.as_view({'get': 'list'})
    
    #Create a dummy user for request
    user = User.objects.first()
    if not user:
        user = User.objects.create_user('testuser', 'test@example.com', 'password')
    request.user = user
    
    response = view(request)
    
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.data
        print(f"Events found: {len(data)}")
        if len(data) > 0:
            print("First event sample:")
            print(data[0])
            
            # Check for keys
            keys = ['id', 'type', 'timestamp', 'summary', 'details', 'severity']
            missing = [k for k in keys if k not in data[0]]
            if missing:
                print(f"ERROR: Missing keys in response: {missing}")
            else:
                print("SUCCESS: Response structure is correct.")
        else:
            print("WARNING: No events returned for user (might be empty).")
    else:
        print("ERROR: API failed.")
        print(response.data)

if __name__ == "__main__":
    verify_timeline()
