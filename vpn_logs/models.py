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
    last_activity = models.DateTimeField(null=True, blank=True, db_index=True, help_text="Carimbo de data/hora do último batimento cardíaco (heartbeat)")
    
    # Campos enriquecidos do AD
    ad_department = models.CharField(max_length=255, null=True, blank=True, db_index=True, help_text="Departamento do usuário (AD)")
    ad_email = models.EmailField(null=True, blank=True, help_text="Email do usuário (AD)")
    ad_title = models.CharField(max_length=255, null=True, blank=True, db_index=True, help_text="Cargo do usuário (AD)")
    ad_display_name = models.CharField(max_length=255, null=True, blank=True, help_text="Nome completo do usuário (AD)")
    
    # Campos GeoIP
    city = models.CharField(max_length=100, null=True, blank=True, help_text="Cidade de origem")
    country_name = models.CharField(max_length=100, null=True, blank=True, help_text="Nome do país")
    country_code = models.CharField(max_length=10, null=True, blank=True, help_text="Código do país (ISO)")
    latitude = models.FloatField(null=True, blank=True, help_text="Latitude do IP de origem")
    longitude = models.FloatField(null=True, blank=True, help_text="Longitude do IP de origem")

    # Campos Calculados (Armazenados para performance)
    is_suspicious = models.BooleanField(default=False, db_index=True, help_text="Indica se o acesso é suspeito (país não confiável)")
    impossible_travel = models.BooleanField(default=False, db_index=True, help_text="Alerta de viagem impossível")
    travel_speed = models.FloatField(null=True, blank=True, help_text="Velocidade estimada (km/h) entre conexões")
    distance_km = models.FloatField(null=True, blank=True, help_text="Distância calculada entre conexões (km)")
    travel_details = models.JSONField(null=True, blank=True, help_text="Contexto da viagem impossível (locais e tempos)")

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
        Calcula a distância entre este login e o anterior usando Haversine.
        Considera impossível se a velocidade necessária exceder 800 km/h (Avião Comercial).
        """
        if not self.user or not self.start_time or not self.latitude or not self.longitude:
            # Se não há dados suficientes para provar que é impossível, assumimos que é possível
            # Isso evita falsos positivos de detecções antigas ou falhas de GeoIP.
            self.impossible_travel = False
            return

        previous_log = VPNLog.objects.filter(
            user=self.user,
            start_time__lt=self.start_time,
            latitude__isnull=False,
            longitude__isnull=False
        ).exclude(id=self.id).order_by('-start_time').first()

        if not previous_log:
            return

        # Mesma localização exata? Possível.
        if previous_log.latitude == self.latitude and previous_log.longitude == self.longitude:
            self.impossible_travel = False
            return

        # Cálculo de Haversine (Distância em KM entre dois pontos)
        import math
        R = 6371.0 # Raio da Terra em KM
        
        lat1, lon1 = math.radians(previous_log.latitude), math.radians(previous_log.longitude)
        lat2, lon2 = math.radians(self.latitude), math.radians(self.longitude)
        
        dlon = lon2 - lon1
        dlat = lat2 - lat1
        
        a = math.sin(dlat / 2)**2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlon / 2)**2
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
        distance = R * c
        
        # Tempo entre conexões
        time_diff = (self.start_time - previous_log.start_time).total_seconds() / 3600.0 # Horas
        
        if time_diff > 0:
            speed = distance / time_diff
            self.travel_speed = round(speed, 2)
            self.distance_km = round(distance, 2)
            
            # Limite: 800 km/h (Avião comercial médio)
            if speed > 800:
                self.impossible_travel = True
                self.travel_details = {
                    'previous': {
                        'city': previous_log.city,
                        'country': previous_log.country_name,
                        'code': previous_log.country_code,
                        'time': previous_log.start_time.isoformat(),
                        'lat': previous_log.latitude,
                        'lon': previous_log.longitude
                    },
                    'current': {
                        'city': self.city,
                        'country': self.country_name,
                        'code': self.country_code,
                        'time': self.start_time.isoformat(),
                        'lat': self.latitude,
                        'lon': self.longitude
                    },
                    'distance_km': self.distance_km,
                    'speed_kmh': self.travel_speed,
                    'time_diff_hours': round(time_diff, 2)
                }
            else:
                self.impossible_travel = False
                self.travel_details = None
        else:
            self.impossible_travel = False

    class Meta:
        verbose_name = "Log de VPN"
        verbose_name_plural = "Logs de VPN"
        ordering = ['-start_time']
        indexes = [
            models.Index(fields=['user', 'start_date']),
            models.Index(fields=['is_suspicious', 'start_date']),
            models.Index(fields=['impossible_travel', 'start_date']),
        ]

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
    country_name = models.CharField(max_length=100, null=True, blank=True)
    latitude = models.FloatField(null=True, blank=True)
    longitude = models.FloatField(null=True, blank=True)

    # Campos enriquecidos do AD
    ad_department = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    ad_email = models.EmailField(null=True, blank=True)
    ad_title = models.CharField(max_length=255, null=True, blank=True, db_index=True)
    ad_display_name = models.CharField(max_length=255, null=True, blank=True)
    
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

