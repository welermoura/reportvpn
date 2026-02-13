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
    impossible_travel = models.BooleanField(default=False, db_index=True, help_text="Alerta de viagem impossível")
    travel_speed = models.FloatField(null=True, blank=True, help_text="Velocidade estimada (km/h) entre conexões")

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
                pass
            
            # Impossible Travel Check
            self._check_impossible_travel()

        super().save(*args, **kwargs)

    def _check_impossible_travel(self):
        """
        Verifica se a viagem desde o último login é factível.
        Critério: Velocidade > 800 km/h (Avião comercial médio).
        """
        if not self.user or not self.start_time or not self.country_code:
            return

        # Buscar último login deste usuário (que tenha localização)
        # Excluir o próprio ID se já salvo (update)
        previous_log = VPNLog.objects.filter(
            user=self.user,
            start_time__lt=self.start_time,
            country_code__isnull=False
        ).exclude(id=self.id).order_by('-start_time').first()

        if not previous_log:
            return

        # Se países são iguais, assumir possível (ignorar cidades por enquanto para evitar falsos positivos de ISP)
        if previous_log.country_code == self.country_code:
            return

        # Calcular distância e tempo
        # Precisamos das coordenadas. Se não temos lat/long no modelo, usamos uma aproximação ou lookup
        # Como o GeoIPClient já retorna, o ideal seria salvar lat/long no model.
        # Por hora, vamos marcar se houver mudança de PAÍS em < 1 hora como regra heurística simples
        
        time_diff = (self.start_time - previous_log.start_time).total_seconds() / 3600.0 # Horas
        
        if time_diff < 1.5: # Mudança de país em menos de 1.5h
             # Permitir fronteiras ou casos específicos seria a evolução ideal
            self.impossible_travel = True
            self.travel_speed = 9999.0 # Placeholder para "Instantâneo"

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

class VPNFailure(models.Model):
    """Modelo para registrar tentativas de falha de login (Brute Force Analysis)"""
    user = models.CharField(max_length=255, db_index=True, help_text="Usuário tentado")
    source_ip = models.GenericIPAddressField(db_index=True, help_text="IP de origem")
    timestamp = models.DateTimeField(db_index=True, help_text="Carimbo de data/hora da falha")
    reason = models.CharField(max_length=255, null=True, blank=True, help_text="Motivo da falha (ex: bad-password)")
    
    # GeoIP (Opcional, mas útil para análise)
    city = models.CharField(max_length=100, null=True, blank=True)
    country_code = models.CharField(max_length=10, null=True, blank=True)
    
    raw_data = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        verbose_name = "Falha de Login VPN"
        verbose_name_plural = "Falhas de Login VPN"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['source_ip', 'timestamp']),
        ]

    def __str__(self):
        return f"Falha: {self.user} em {self.timestamp}"

