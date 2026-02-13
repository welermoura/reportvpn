from django.db import models
from django.contrib.auth.models import User

class Profile(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    force_password_change = models.BooleanField(default=True, verbose_name="Forçar troca de senha")

    def __str__(self):
        return f'{self.user.username} Profile'

class PortalModule(models.Model):
    title = models.CharField(max_length=100, verbose_name="Título")
    slug = models.SlugField(unique=True, verbose_name="Identificador (Slug)")
    icon = models.CharField(max_length=50, default="📊", help_text="Emoji ou classe de ícone (ex: 📊, 🛡️, fa-solid fa-shield)", verbose_name="Ícone")
    description = models.TextField(blank=True, verbose_name="Descrição")
    url_name = models.CharField(max_length=200, help_text="Nome da rota Django (ex: dashboard:vpn_reports) ou URL absoluta", verbose_name="Rota/URL")
    order = models.IntegerField(default=0, verbose_name="Ordem de Exibição")
    is_active = models.BooleanField(default=True, verbose_name="Ativo?")

    class Meta:
        verbose_name = "Módulo do Portal"
        verbose_name_plural = "Módulos do Portal"
        ordering = ['order']

    def __str__(self):
        return self.title

class AccessLog(models.Model):
    user = models.ForeignKey(User, on_delete=models.SET_NULL, null=True, verbose_name="Usuário")
    path = models.CharField(max_length=255, verbose_name="Caminho Acessado")
    ip_address = models.GenericIPAddressField(verbose_name="Endereço IP", null=True, blank=True)
    method = models.CharField(max_length=10, verbose_name="Método HTTP")
    timestamp = models.DateTimeField(auto_now_add=True, verbose_name="Data/Hora")

    class Meta:
        verbose_name = "Log de Acesso"
        verbose_name_plural = "Logs de Acesso"
        ordering = ['-timestamp']

    def __str__(self):
        return f"{self.user} - {self.path} - {self.timestamp}"
