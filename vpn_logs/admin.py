from django.contrib import admin

from .models import VPNLog

@admin.register(VPNLog)
class VPNLogAdmin(admin.ModelAdmin):
    list_display = ('user', 'source_ip', 'status', 'start_time', 'end_time', 'duration', 'is_suspicious', 'country_code')
    list_filter = ('status', 'is_suspicious', 'country_code', 'start_date')
    search_fields = ('user', 'source_ip', 'session_id', 'ad_department')
    date_hierarchy = 'start_time'
    readonly_fields = ('created_at', 'updated_at', 'raw_data')

    def formatted_volume(self, obj):
        # Implementation if needed, or stick to bytes for simplicity in list_display
        return f"{obj.bandwidth_in + obj.bandwidth_out} bytes"
    formatted_volume.short_description = "Volume Total"
