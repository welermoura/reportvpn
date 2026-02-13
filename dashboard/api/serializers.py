from rest_framework import serializers

class VPNLogAggregatedSerializer(serializers.Serializer):
    user = serializers.CharField()
    ad_display_name = serializers.CharField(allow_null=True)
    ad_department = serializers.CharField(allow_null=True)
    ad_title = serializers.CharField(allow_null=True)
    total_connections = serializers.IntegerField()
    total_duration = serializers.IntegerField()
    total_volume = serializers.IntegerField()
    last_connection = serializers.DateTimeField()
    latest_source_ip = serializers.IPAddressField(allow_null=True)
    latest_city = serializers.CharField(allow_null=True)
    latest_country = serializers.CharField(allow_null=True)
    latest_country = serializers.CharField(allow_null=True)
    latest_country_code = serializers.CharField(allow_null=True)

class VPNLogSerializer(serializers.ModelSerializer):
    """Serializer for individual VPN Log entries (History)"""
    total_volume = serializers.SerializerMethodField()
    formatted_duration = serializers.ReadOnlyField()

    class Meta:
        from vpn_logs.models import VPNLog
        model = VPNLog
        fields = [
            'id', 'start_time', 'end_time', 'duration', 'formatted_duration',
            'user', 'source_ip', 'city', 'country_name', 'country_code',
            'bandwidth_in', 'bandwidth_out', 'total_volume',
            'status'
        ]

    def get_total_volume(self, obj):
        return (obj.bandwidth_in or 0) + (obj.bandwidth_out or 0)

class VPNFailureSerializer(serializers.ModelSerializer):
    """Serializer for VPN Failure entries"""
    class Meta:
        from vpn_logs.models import VPNFailure
        model = VPNFailure
        fields = '__all__'
