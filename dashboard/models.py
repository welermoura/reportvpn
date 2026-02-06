from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    force_password_change = models.BooleanField(default=True, verbose_name="Forçar troca de senha")

    def __str__(self):
        return f'{self.user.username} Profile'
