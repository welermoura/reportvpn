from django.db import models

class SingletonModel(models.Model):
    """Abstract model that ensures only one instance exists."""
    class Meta:
        abstract = True

    def save(self, *args, **kwargs):
        self.pk = 1
        super(SingletonModel, self).save(*args, **kwargs)

    @classmethod
    def load(cls):
        obj, created = cls.objects.get_or_create(pk=1)
        return obj

class FortiAnalyzerConfig(SingletonModel):
    host = models.CharField(max_length=255, default="https://fortianalyzer.example.com")
    port = models.IntegerField(default=443)
    adom = models.CharField(max_length=100, default="root", help_text="Nome do ADOM (ex: root)")
    api_token = models.CharField(max_length=512, help_text="Token de API gerado no FortiAnalyzer")
    verify_ssl = models.BooleanField(default=False, help_text="Verificar certificado SSL?")
    trusted_countries = models.TextField(default="BR", help_text="Códigos de países confiáveis, separados por vírgula (ex: BR,US)")
    
    def __str__(self):
        return "Configuração do FortiAnalyzer"

    class Meta:
        verbose_name = "Configuração FortiAnalyzer"
        verbose_name_plural = "Configuração FortiAnalyzer"

class ActiveDirectoryConfig(SingletonModel):
    server = models.CharField(max_length=255, default="ldap.example.com", help_text="Endereço do DC")
    port = models.IntegerField(default=389)
    use_ssl = models.BooleanField(default=False, help_text="Usar LDAPS?")
    base_dn = models.CharField(max_length=255, default="DC=example,DC=com")
    bind_user = models.CharField(max_length=255, help_text="Usuário para bind (ex: CN=BindUser,OU=ServiceAccounts,DC=example,DC=com)")
    bind_password = models.CharField(max_length=255, help_text="Senha do usuário de bind")
    
    def __str__(self):
        return "Configuração do Active Directory"

    class Meta:
        verbose_name = "Configuração Active Directory"
        verbose_name_plural = "Configuração Active Directory"
