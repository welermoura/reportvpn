import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings')
django.setup()

from django.contrib.auth.models import User
from dashboard.models import Profile

username = 'admin'
password = 'admin'
email = 'admin@example.com'

try:
    user = User.objects.get(username=username)
    user.set_password(password)
    user.save()
    print(f"Updated password for existing user: {username}")
except User.DoesNotExist:
    user = User.objects.create_superuser(username, email, password)
    print(f"Created new superuser: {username}")

# Ensure profile enforces change
if not hasattr(user, 'profile'):
    Profile.objects.create(user=user)

user.profile.force_password_change = True
user.profile.save()
print(f"Force password change set to True for {username}")
