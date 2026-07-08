from django.contrib import admin
from .models import FortiAnalyzerConfig, ActiveDirectoryConfig, ConfigAuditLog


class SingletonModelAdmin(admin.ModelAdmin):
    """Prevents deletion and adding new instances if one already exists."""
    def has_add_permission(self, request):
        if self.model.objects.exists():
            return False
        return super().has_add_permission(request)

    def has_delete_permission(self, request, obj=None):
        return False

    def save_model(self, request, obj, form, change):
        obj._audit_user = request.user
        super().save_model(request, obj, form, change)


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


@admin.register(ActiveDirectoryConfig)
class ActiveDirectoryConfigAdmin(SingletonModelAdmin):
    list_display = ('server', 'port', 'use_ssl', 'validate_certificate', 'base_dn')
    fieldsets = (
        ('Servidor', {
            'fields': ('server', 'port', 'use_ssl', 'validate_certificate', 'ca_cert_file')
        }),
        ('Autenticação e Busca', {
            'fields': ('base_dn', 'bind_user', 'bind_password')
        }),
    )


@admin.register(ConfigAuditLog)
class ConfigAuditLogAdmin(admin.ModelAdmin):
    list_display = ('config_type', 'changed_by', 'changed_at', 'changed_fields_summary')
    list_filter = ('config_type', 'changed_by')
    readonly_fields = ('config_type', 'changed_by', 'changed_at', 'changes')
    ordering = ('-changed_at',)

    def has_add_permission(self, request):
        return False

    def has_delete_permission(self, request, obj=None):
        return False

    def has_change_permission(self, request, obj=None):
        return False

    def changed_fields_summary(self, obj):
        return ', '.join(obj.changes.keys()) if obj.changes else '—'
    changed_fields_summary.short_description = "Campos Alterados"

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
