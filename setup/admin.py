from django.contrib import admin
from .models import DatabaseConfiguration, SetupProgress


@admin.register(DatabaseConfiguration)
class DatabaseConfigurationAdmin(admin.ModelAdmin):
    list_display = ('db_type', 'host', 'port', 'database_name', 'is_configured', 'configured_at')
    list_filter = ('db_type', 'is_configured')
    search_fields = ('host', 'database_name', 'username')
    readonly_fields = ('configured_at', 'updated_at')
    
    fieldsets = (
        ('Database Information', {
            'fields': ('db_type', 'host', 'port', 'database_name')
        }),
        ('Credentials', {
            'fields': ('username', 'encrypted_password'),
            'classes': ('collapse',)
        }),
        ('Status', {
            'fields': ('is_configured', 'configured_at', 'updated_at')
        }),
    )


@admin.register(SetupProgress)
class SetupProgressAdmin(admin.ModelAdmin):
    list_display = ('current_step', 'is_complete', 'started_at', 'completed_at')
    list_filter = ('is_complete', 'current_step')
    readonly_fields = ('started_at', 'completed_at')
