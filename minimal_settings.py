from vpn_dashboard.settings import *

# Remove jazzmin to avoid import errors if not installed on host
if 'jazzmin' in INSTALLED_APPS:
    INSTALLED_APPS.remove('jazzmin')
