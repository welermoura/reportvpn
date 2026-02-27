from django.db import models
from django.db.models import Q
import logging

logger = logging.getLogger(__name__)

def sync_celery_tasks(enabled):
    """Enable or disable polling tasks based on FA config status."""
    try:
        from django_celery_beat.models import PeriodicTask
        task_names = [
            'Coleta de Logs VPN (10 min)',
            'Coleta de Eventos IPS (10 min)',
            'Coleta de Eventos Antivirus (10 min)',
            'Coleta de Eventos Web Filter (10 min)',
            'Coleta de Eventos App Control (10 min)',
            'Coleta de Eventos App Control (5 min)',
            'Coleta de Logs VPN (5 min)',
            'Coleta de Eventos IPS (5 min)',
            'Coleta de Eventos Antivirus (5 min)',
            'Coleta de Eventos Web Filter (5 min)',
        ]
        # Adicionalmente, podemos filtrar por icontains para ser mais resiliente
        PeriodicTask.objects.filter(Q(name__in=task_names) | Q(name__icontains='Coleta de Eventos')).update(enabled=enabled)
        logger.info(f"Celery tasks {'enabled' if enabled else 'disabled'} successfully.")
    except Exception as e:
        logger.error(f"Error syncing celery tasks: {e}")

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
    is_enabled = models.BooleanField(default=True, help_text="Ativar a coleta ativa (Polling) via API do FortiAnalyzer?")
    
    def save(self, *args, **kwargs):
        # Mutual Exclusion
        if self.is_enabled:
            SyslogConfig.objects.all().update(is_enabled=False)
        
        # Sync Tasks
        sync_celery_tasks(self.is_enabled)
        
        super().save(*args, **kwargs)

    def __str__(self):
        return "Configuração: Coleta via API (FortiAnalyzer)"

    class Meta:
        verbose_name = "Coleta via API (FortiAnalyzer)"
        verbose_name_plural = "Coleta via API (FortiAnalyzer)"

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

class SyslogConfig(SingletonModel):
    is_enabled = models.BooleanField(default=False, help_text="Ativar a recepção passiva de logs via Syslog UDP?")
    port = models.IntegerField(default=5140, help_text="Porta UDP para escuta (Padrão 5140)")
    
    def save(self, *args, **kwargs):
        # Mutual Exclusion
        if self.is_enabled:
            fa_configs = FortiAnalyzerConfig.objects.all()
            for config in fa_configs:
                if config.is_enabled:
                    config.is_enabled = False
                    config.save() # This will call sync_celery_tasks(False)
        
        super().save(*args, **kwargs)

    def __str__(self):
        return "Configuração: Coleta via Syslog (Real-time)"

    class Meta:
        verbose_name = "Coleta em Tempo Real (Syslog)"
        verbose_name_plural = "Coleta em Tempo Real (Syslog)"

class KnownDevice(models.Model):
    device_id = models.CharField(max_length=100, unique=True, help_text="ID/Serial Number do Dispositivo (ex: FGT60E...)")
    hostname = models.CharField(max_length=255, blank=True, null=True)
    ip_address = models.GenericIPAddressField(help_text="Último IP de origem detectado")
    device_type = models.CharField(max_length=50, default="fortigate", help_text="Fabricante/Tipo detectado")
    last_seen = models.DateTimeField(auto_now=True)
    is_authorized = models.BooleanField(default=True, help_text="Indica se este dispositivo é uma fonte confiável")
    last_alert_message = models.CharField(max_length=500, blank=True, null=True, help_text="Último alerta de sistema (CPU/Memória/Link)")
    last_alert_time = models.DateTimeField(blank=True, null=True)
    
    # Status Detalhado de Hardware
    cpu_status = models.CharField(max_length=50, default="normal", help_text="Estado da CPU (normal/alto)")
    memory_status = models.CharField(max_length=50, default="normal", help_text="Estado da Memória (normal/alto)")
    link_status = models.CharField(max_length=50, default="normal", help_text="Estado dos Links (normal/alarme)")
    conserve_mode = models.BooleanField(default=False, help_text="Indica se o dispositivo está em Conserve Mode")
    
    # Portas Monitoradas (SD-WAN / Health Checks)
    monitored_ports = models.JSONField(default=list, blank=True, help_text="Lista de portas monitoradas: [{'name': 'wan1', 'alias': 'Internet'}]")
    
    def __str__(self):
        return f"{self.hostname or self.device_id} ({self.ip_address})"

    class Meta:
        verbose_name = "Dispositivo Emissor (Inventory)"
        verbose_name_plural = "Dispositivos Emissores (Inventory)"
        ordering = ['-last_seen']
