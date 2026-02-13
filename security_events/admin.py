"""Security Events Admin"""
from django.contrib import admin
from .models import SecurityEvent


@admin.register(SecurityEvent)
class SecurityEventAdmin(admin.ModelAdmin):
    list_display = ('timestamp', 'event_type', 'severity', 'src_ip', 'dst_ip', 'username', 'action')
    list_filter = ('event_type', 'severity', 'date', 'action')
    search_fields = ('src_ip', 'dst_ip', 'username', 'attack_name', 'virus_name', 'url')
    date_hierarchy = 'timestamp'
    readonly_fields = ('event_id', 'created_at', 'raw_log')
    
    fieldsets = (
        ('Informações Básicas', {
            'fields': ('event_id', 'event_type', 'severity', 'timestamp', 'date')
        }),
        ('Rede', {
            'fields': ('src_ip', 'src_port', 'src_country', 'dst_ip', 'dst_port', 'dst_country')
        }),
        ('Usuário', {
            'fields': ('username', 'user_email', 'user_department')
        }),
        ('IPS', {
            'fields': ('attack_name', 'attack_id', 'cve'),
            'classes': ('collapse',)
        }),
        ('Antivirus', {
            'fields': ('virus_name', 'file_name', 'file_hash'),
            'classes': ('collapse',)
        }),
        ('Web Filter', {
            'fields': ('url', 'category', 'action'),
            'classes': ('collapse',)
        }),
        ('Metadados', {
            'fields': ('raw_log', 'created_at'),
            'classes': ('collapse',)
        }),
    )
