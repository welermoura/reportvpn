from django.db.models.signals import post_save, pre_save
from django.dispatch import receiver
from django.contrib.auth.models import User
from .models import Profile

@receiver(post_save, sender=User)
def create_user_profile(sender, instance, created, **kwargs):
    if created:
        Profile.objects.create(user=instance)

@receiver(post_save, sender=User)
def save_user_profile(sender, instance, **kwargs):
    if not hasattr(instance, 'profile'):
        Profile.objects.create(user=instance)
    instance.profile.save()

@receiver(pre_save, sender=User)
def check_password_change(sender, instance, **kwargs):
    # If user exists (not creating), check if password changed
    if instance.pk:
        try:
            old_user = User.objects.get(pk=instance.pk)
            if instance.password != old_user.password:
                # Password has changed
                if hasattr(instance, 'profile'):
                    instance.profile.force_password_change = False
                    instance.profile.save()
        except User.DoesNotExist:
            pass
