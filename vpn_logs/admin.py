from django.contrib import admin

from .models import VPNLog

@admin.register(VPNLog)
class VPNLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'source_ip', 'start_time', 'duration', 'formatted_volume', 'city', 'country_code', 'is_suspicious')
    list_filter = ('start_date', 'country_code', 'is_suspicious', 'status')
    search_fields = ('user', 'source_ip', 'ad_department', 'ad_title', 'city')
    readonly_fields = ('created_at', 'updated_at')
    date_hierarchy = 'start_time'
