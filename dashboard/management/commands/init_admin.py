from django.core.management.base import BaseCommand
from django.contrib.auth.models import User
from dashboard.models import Profile

class Command(BaseCommand):
    help = 'Resets or creates the admin user with default credentials and forced password change.'

    def handle(self, *args, **options):
        username = 'admin'
        password = 'admin'
        email = 'admin@example.com'

        try:
            user = User.objects.get(username=username)
            user.set_password(password)
            user.save()
            self.stdout.write(self.style.SUCCESS(f"Updated password for existing user: {username}"))
        except User.DoesNotExist:
            user = User.objects.create_superuser(username, email, password)
            self.stdout.write(self.style.SUCCESS(f"Created new superuser: {username}"))

        # Ensure profile enforces change
        if not hasattr(user, 'profile'):
            Profile.objects.create(user=user)

        user.profile.force_password_change = True
        user.profile.save()
        self.stdout.write(self.style.SUCCESS(f"Force password change set to True for {username}"))
