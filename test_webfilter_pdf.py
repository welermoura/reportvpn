from django.test import RequestFactory
try:
    from security_events.views import export_webfilter_pdf
except ImportError as e:
    print(f"ImportError importing view: {e}")
    exit(1)
except Exception as e:
    print(f"Error importing view: {e}")
    exit(1)
from django.contrib.auth.models import User

try:
    user = User.objects.first()
    if not user:
        print("No user found!")
        exit(1)

    factory = RequestFactory()
    request = factory.get('/security/export/webfilter/pdf/')
    request.user = user

    print("Testing Webfilter PDF Export...")
    response = export_webfilter_pdf(request)
    print(f"Webfilter PDF Status: {response.status_code}")
    if response.status_code == 200:
        print(f"Webfilter PDF Size: {len(response.content)} bytes")
    else:
        print(f"Webfilter PDF Error Content: {response.content.decode('utf-8')[:500]}")

except Exception as e:
    print(f"Exception during test: {e}")
    import traceback
    traceback.print_exc()
