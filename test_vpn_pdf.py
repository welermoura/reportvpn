from django.test import RequestFactory
from dashboard.views import export_logs_pdf
from django.contrib.auth.models import User
from django.utils import timezone

try:
    # Create valid user if needed, or get first
    user = User.objects.first()
    if not user:
        print("No user found!")
        exit(1)

    factory = RequestFactory()
    request = factory.get('/export/pdf/')
    request.user = user

    print("Testing VPN PDF Export...")
    response = export_logs_pdf(request)
    print(f"VPN PDF Status: {response.status_code}")
    if response.status_code == 200:
        print(f"VPN PDF Size: {len(response.content)} bytes")
    else:
        print(f"VPN PDF Error Content: {response.content.decode('utf-8')[:500]}")

except Exception as e:
    print(f"Exception during test: {e}")
    import traceback
    traceback.print_exc()
