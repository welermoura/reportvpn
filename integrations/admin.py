from .models import FortiAnalyzerConfig, ActiveDirectoryConfig

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
