from django.contrib import admin
from .models import FortiAnalyzerConfig, ActiveDirectoryConfig, SyslogConfig, KnownDevice

class SingletonModelAdmin(admin.ModelAdmin):
    """
    Prevents deletion and adding new instances if one already exists.
    """
    def has_add_permission(self, request):
        if self.model.objects.exists():
            return False
        return super().has_add_permission(request)

    def has_delete_permission(self, request, obj=None):
        return False

@admin.register(FortiAnalyzerConfig)
class FortiAnalyzerConfigAdmin(SingletonModelAdmin):
    list_display = ('host', 'port', 'adom', 'verify_ssl')
    fieldsets = (
        ('Conexão', {
            'fields': ('host', 'port', 'adom', 'verify_ssl')
        }),
        ('Autenticação', {
            'fields': ('api_token', 'trusted_countries', 'is_enabled')
        }),
    )

@admin.register(SyslogConfig)
class SyslogConfigAdmin(SingletonModelAdmin):
    list_display = ('is_enabled', 'port')
    fieldsets = (
        ('Controle', {
            'fields': ('is_enabled', 'port')
        }),
    )

@admin.register(ActiveDirectoryConfig)
class ActiveDirectoryConfigAdmin(SingletonModelAdmin):
    list_display = ('server', 'port', 'use_ssl', 'base_dn')
    fieldsets = (
        ('Servidor', {
            'fields': ('server', 'port', 'use_ssl')
        }),
        ('Autenticação e Busca', {
            'fields': ('base_dn', 'bind_user', 'bind_password')
        }),
    )

@admin.register(KnownDevice)
class KnownDeviceAdmin(admin.ModelAdmin):
    list_display = ('device_id', 'hostname', 'ip_address', 'device_type', 'last_seen', 'is_authorized')
    list_filter = ('device_type', 'is_authorized')
    search_fields = ('device_id', 'hostname', 'ip_address')
    readonly_fields = ('last_seen',)
    actions = ['mark_as_unauthorized', 'mark_as_authorized']

    def mark_as_unauthorized(self, request, queryset):
        queryset.update(is_authorized=False)
    mark_as_unauthorized.short_description = "Desautorizar dispositivos selecionados"

    def mark_as_authorized(self, request, queryset):
        queryset.update(is_authorized=True)
    mark_as_authorized.short_description = "Autorizar dispositivos selecionados"

# Customized Group Admin to allow AD Search
from django.contrib.auth.models import Group
from django.contrib.auth.admin import GroupAdmin as BaseGroupAdmin

admin.site.unregister(Group)

@admin.register(Group)
class GroupAdmin(BaseGroupAdmin):
    class Media:
        css = {
            'all': ('https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/css/select2.min.css',)
        }
        js = (
            'https://code.jquery.com/jquery-3.6.0.min.js',
            'https://cdn.jsdelivr.net/npm/select2@4.1.0-rc.0/dist/js/select2.min.js',
            'admin/js/ad_group_select.js', 
        )
