import os
import django

import sys
from django.conf import settings

sys.path.append(os.getcwd())

if not settings.configured:
    settings.configure(
        DATABASES={
            'default': {
                'ENGINE': 'mssql',
                'NAME': 'VPN_SIEM',
                'USER': 'vpn_siem',
                'PASSWORD': 'vpn@2026',
                'HOST': '10.10.1.95',
                'PORT': '1433',
                'OPTIONS': {
                    'driver': 'ODBC Driver 18 for SQL Server',
                    'extra_params': 'TrustServerCertificate=yes',
                },
            }
        },
        INSTALLED_APPS=[
            'vpn_logs',
        ],
        TIME_ZONE='UTC',
        USE_TZ=True,
    )
django.setup()

from vpn_logs.models import VPNLog

user = 'mariajr'
print(f"Checking for user: {user}")
print(f"Count exact: {VPNLog.objects.filter(user=user).count()}")
print(f"Count iexact: {VPNLog.objects.filter(user__iexact=user).count()}")
print(f"Count icontains: {VPNLog.objects.filter(user__icontains=user).count()}")

# Show some samples
print("Sample users in DB:")
for u in VPNLog.objects.values_list('user', flat=True).distinct()[:10]:
    print(f"'{u}'")
