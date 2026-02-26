"""Security Events Models"""
from django.db import models
from django.utils import timezone


class SecurityEvent(models.Model):
    """Model for security events from FortiAnalyzer"""
    
    EVENT_TYPES = [
        ('ips', 'IPS'),
        ('antivirus', 'Antivirus'),
        ('webfilter', 'Web Filter'),
        ('app-control', 'App Control'),
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
    
    # App Control Específico
    app_name = models.CharField(max_length=255, blank=True)
    app_category = models.CharField(max_length=255, blank=True)
    app_risk = models.CharField(max_length=50, blank=True)
    bytes_in = models.BigIntegerField(null=True, blank=True)
    bytes_out = models.BigIntegerField(null=True, blank=True)
    
    # Metadados
    raw_log = models.TextField()
    created_at = models.DateTimeField(auto_now_add=True)
    
    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['event_type', 'date', 'severity']),
            models.Index(fields=['event_type', 'date', 'action']),
            models.Index(fields=['event_type', 'date', 'app_category']),
            models.Index(fields=['event_type', 'date', 'username']),
            models.Index(fields=['username', 'date']),
            models.Index(fields=['-timestamp']),
            models.Index(fields=['event_type', 'date', 'attack_name']),
            models.Index(fields=['event_type', 'date', 'virus_name']),
            models.Index(fields=['event_type', '-timestamp']),
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


class ADAuthEvent(models.Model):
    """Model for Active Directory Authentication Events (Logon/Logoff/Lockout)"""
    
    STATUS_CHOICES = [
        ('success', 'Sucesso'),
        ('failed', 'Falha'),
        ('locked', 'Conta Bloqueada'),
    ]

    username = models.CharField(max_length=255, db_index=True, verbose_name="Usuário")
    workstation = models.CharField(max_length=255, blank=True, verbose_name="Estação/Computador")
    src_ip = models.GenericIPAddressField(null=True, blank=True, verbose_name="IP de Origem")
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, db_index=True)
    event_id = models.IntegerField(db_index=True, verbose_name="Event ID (Windows)")
    message = models.TextField(blank=True, verbose_name="Mensagem Original")
    
    # AD Context
    ad_department = models.CharField(max_length=255, blank=True)
    ad_title = models.CharField(max_length=255, blank=True)
    ad_display_name = models.CharField(max_length=255, blank=True)
    
    timestamp = models.DateTimeField(db_index=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['username', 'timestamp']),
            models.Index(fields=['status', 'timestamp']),
            models.Index(fields=['event_id', 'timestamp']),
        ]
        verbose_name = 'Evento de Autenticação AD'
        verbose_name_plural = 'Eventos de Autenticação AD'

    def __str__(self):
        return f"{self.username} - {self.get_status_display()} ({self.timestamp})"


# =========================================================
# RADAR AD (Auditoria de Postura LDAP - Módulo 3 Novo)
# =========================================================

class ADUser(models.Model):
    username = models.CharField(max_length=255, db_index=True)
    sid = models.CharField(max_length=150, unique=True)
    display_name = models.CharField(max_length=255, null=True, blank=True)
    department = models.CharField(max_length=255, null=True, blank=True)
    title = models.CharField(max_length=255, null=True, blank=True)
    
    last_logon = models.DateTimeField(null=True, blank=True)
    pwd_last_set = models.DateTimeField(null=True, blank=True)
    
    is_inactive = models.BooleanField(default=False)
    is_disabled = models.BooleanField(default=False)
    is_privileged = models.BooleanField(default=False)
    
    last_seen = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = "Usuário do AD (Radar)"
        verbose_name_plural = "Usuários do AD (Radar)"
        ordering = ['username']

    def __str__(self):
        return self.username

class ADGroup(models.Model):
    cn = models.CharField(max_length=255, db_index=True)
    sid = models.CharField(max_length=150, unique=True)
    is_privileged = models.BooleanField(default=False)
    weight = models.IntegerField(default=0)
    
    last_seen = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Grupo do AD (Radar)"
        verbose_name_plural = "Grupos do AD (Radar)"

    def __str__(self):
        return self.cn

class ADMemberOf(models.Model):
    # Relacionamento M:N com metadados e cache grafo
    user = models.ForeignKey(ADUser, on_delete=models.CASCADE, null=True, blank=True, related_name='group_memberships')
    group = models.ForeignKey(ADGroup, on_delete=models.CASCADE, null=True, blank=True, related_name='group_memberships')
    
    parent_group = models.ForeignKey(ADGroup, on_delete=models.CASCADE, null=True, blank=True, related_name='child_groups')

    class Meta:
        verbose_name = "Associação AD (Radar)"
        verbose_name_plural = "Associações AD (Radar)"

class ADRiskSnapshot(models.Model):
    timestamp = models.DateTimeField(auto_now_add=True)
    
    total_users = models.IntegerField(default=0)
    total_groups = models.IntegerField(default=0)
    
    privileged_users_count = models.IntegerField(default=0)
    inactive_privileged_count = models.IntegerField(default=0)
    disabled_privileged_count = models.IntegerField(default=0)
    
    # NOVOS CAMPOS JSON PARA O BFS AVANÇADO DO RADAR
    chart_data = models.JSONField(null=True, blank=True)
    findings_data = models.JSONField(null=True, blank=True)
    direct_members_data = models.JSONField(null=True, blank=True)
    inactive_users_data = models.JSONField(null=True, blank=True)

    class Meta:
        ordering = ['-timestamp']
        verbose_name = "Snapshot de Risco AD"
        verbose_name_plural = "Snapshots de Risco AD"

    def __str__(self):
        return f"Snapshot LDAP - {self.timestamp}"

