from django.db import models

# Create your models here.

class VPNLog(models.Model):
    session_id = models.CharField(max_length=255, unique=True, help_text="ID único da sessão no FortiAnalyzer")
    user = models.CharField(max_length=255, db_index=True, help_text="Nome de usuário da VPN")
    source_ip = models.GenericIPAddressField(help_text="IP de origem da conexão")
    start_time = models.DateTimeField(db_index=True, help_text="Data e hora de início da conexão")
    start_date = models.DateField(null=True, blank=True, db_index=True, help_text="Data de início (para otimização)")
    end_time = models.DateTimeField(null=True, blank=True, help_text="Data e hora de fim da conexão")
    duration = models.IntegerField(null=True, blank=True, help_text="Duração em segundos")
    bandwidth_in = models.BigIntegerField(default=0, help_text="Bytes recebidos")
    bandwidth_out = models.BigIntegerField(default=0, help_text="Bytes enviados")
    status = models.CharField(max_length=50, help_text="Status da conexão (ex: tunnel-up, tunnel-down)")
    
    # Campos enriquecidos do AD
    ad_department = models.CharField(max_length=255, null=True, blank=True, db_index=True, help_text="Departamento do usuário (AD)")
    ad_email = models.EmailField(null=True, blank=True, help_text="Email do usuário (AD)")
    ad_title = models.CharField(max_length=255, null=True, blank=True, db_index=True, help_text="Cargo do usuário (AD)")
    ad_display_name = models.CharField(max_length=255, null=True, blank=True, help_text="Nome completo do usuário (AD)")
    
    # Campos GeoIP
    city = models.CharField(max_length=100, null=True, blank=True, help_text="Cidade de origem")
    country_name = models.CharField(max_length=100, null=True, blank=True, help_text="Nome do país")
    country_code = models.CharField(max_length=10, null=True, blank=True, help_text="Código do país (ISO)")

    # Campos Calculados (Armazenados para performance)
    is_suspicious = models.BooleanField(default=False, db_index=True, help_text="Indica se o acesso é suspeito (país não confiável)")

    
    raw_data = models.JSONField(default=dict, help_text="Dados brutos do log")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def save(self, *args, **kwargs):
        if self.start_time and not self.start_date:
            self.start_date = self.start_time.date()
            
        # Calcular is_suspicious se não for bypassado (para performance em bulk)
        if not getattr(self, 'bypass_suspicious_check', False):
            from integrations.models import FortiAnalyzerConfig
            try:
                config = FortiAnalyzerConfig.load()
                trusted = [c.strip().upper() for c in config.trusted_countries.split(',')]
                code = self.country_code.upper() if self.country_code else None
                
                # Se não tem código, assumimos não suspeito (ou política definida)
                # Se tem código e não está na lista, é suspeito
                if code and code not in trusted:
                    self.is_suspicious = True
                else:
                    self.is_suspicious = False
            except Exception:
                # Fallback em caso de erro no config (migrações inicializando, etc)
                pass

        super().save(*args, **kwargs)

    class Meta:
        verbose_name = "Log de VPN"
        verbose_name_plural = "Logs de VPN"
        ordering = ['-start_time']

    def __str__(self):
        return f"{self.user} - {self.start_time}"

    def formatted_duration(self):
        if not self.duration:
            return "-"
        seconds = self.duration
        h = seconds // 3600
        m = (seconds % 3600) // 60
        s = seconds % 60
        return f"{h:02d}:{m:02d}:{s:02d}"
        
    def formatted_volume(self):
        total = (self.bandwidth_in or 0) + (self.bandwidth_out or 0)
        if total == 0:
            return "-"
        # Converter para GB ou MB
        gb = total / (1024 * 1024 * 1024)
        if gb >= 1:
            return f"{gb:.2f} GB"
        mb = total / (1024 * 1024)
        return f"{mb:.2f} MB"

    @property
    def display_name_or_user(self):
        return self.ad_display_name or self.user

