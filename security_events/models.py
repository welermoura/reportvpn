"""Security Events Models"""
from django.db import models
from django.utils import timezone


class SecurityEvent(models.Model):
    """Model for security events from FortiAnalyzer"""
    
    EVENT_TYPES = [
        ('ips', 'IPS'),
        ('antivirus', 'Antivirus'),
        ('webfilter', 'Web Filter'),
    ]
    
    SEVERITY_LEVELS = [
        ('critical', 'Crítico'),
        ('high', 'Alto'),
        ('medium', 'Médio'),
        ('low', 'Baixo'),
        ('info', 'Informativo'),
    ]
    
    # Identificação
    event_id = models.CharField(max_length=100, unique=True, db_index=True)
    event_type = models.CharField(max_length=20, choices=EVENT_TYPES, db_index=True)
    severity = models.CharField(max_length=20, choices=SEVERITY_LEVELS, db_index=True)
    
    # Temporal
    timestamp = models.DateTimeField(db_index=True)
    date = models.DateField(db_index=True)
    
    # Origem e Destino
    src_ip = models.GenericIPAddressField()
    dst_ip = models.GenericIPAddressField()
    src_port = models.IntegerField(null=True, blank=True)
    dst_port = models.IntegerField(null=True, blank=True)
    
    # Geolocalização
    src_country = models.CharField(max_length=100, blank=True)
    dst_country = models.CharField(max_length=100, blank=True)
    
    # Usuário
    username = models.CharField(max_length=255, blank=True, db_index=True)
    user_email = models.EmailField(blank=True)
    user_department = models.CharField(max_length=255, blank=True)
    ad_title = models.CharField(max_length=255, blank=True, verbose_name="Cargo (AD)")
    ad_display_name = models.CharField(max_length=255, blank=True, verbose_name="Nome de Exibição (AD)")
    
    # IPS Específico
    attack_name = models.CharField(max_length=500, blank=True)
    attack_id = models.CharField(max_length=100, blank=True)
    cve = models.CharField(max_length=100, blank=True)
    
    # Antivirus Específico
    virus_name = models.CharField(max_length=500, blank=True)
    file_name = models.CharField(max_length=500, blank=True)
    file_hash = models.CharField(max_length=128, blank=True)
    
    # Web Filter Específico
    url = models.TextField(blank=True)
    category = models.CharField(max_length=255, blank=True)
    action = models.CharField(max_length=50)  # blocked, allowed, monitored
    
    # Metadados
    raw_log = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'date']),
            models.Index(fields=['severity', 'date']),
            models.Index(fields=['username', 'date']),
            models.Index(fields=['-timestamp']),
        ]
        verbose_name = 'Evento de Segurança'
        verbose_name_plural = 'Eventos de Segurança'
    
    def __str__(self):
        return f"{self.get_event_type_display()} - {self.severity} - {self.timestamp}"
    
    def get_severity_color(self):
        """Return color class for severity level"""
        colors = {
            'critical': 'danger',
            'high': 'warning',
            'medium': 'info',
            'low': 'secondary',
            'info': 'light',
        }
        return colors.get(self.severity, 'secondary')
