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
    latest_status = serializers.CharField(allow_null=True)

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
    """Serializer for VPN Failure entries with enriched AD data"""
    ad_display_name = serializers.SerializerMethodField()
    ad_department = serializers.SerializerMethodField()
    ad_title = serializers.SerializerMethodField()

    class Meta:
        from vpn_logs.models import VPNFailure
        model = VPNFailure
        fields = '__all__'

    def _get_ad_info(self, obj):
        if not hasattr(self, '_ad_cache'):
            self._ad_cache = {}
        
        if obj.user not in self._ad_cache:
            from vpn_logs.models import VPNLog
            # Buscar o log mais recente desse usuário que tenha dados do AD
            latest_ad_log = VPNLog.objects.filter(user=obj.user).exclude(ad_display_name__isnull=True).exclude(ad_display_name='').order_by('-start_time').first()
            if latest_ad_log:
                self._ad_cache[obj.user] = {
                    'name': latest_ad_log.ad_display_name,
                    'dept': latest_ad_log.ad_department,
                    'title': latest_ad_log.ad_title
                }
            else:
                self._ad_cache[obj.user] = None
        return self._ad_cache[obj.user]

    def get_ad_display_name(self, obj):
        info = self._get_ad_info(obj)
        return info['name'] if info else None

    def get_ad_department(self, obj):
        info = self._get_ad_info(obj)
        return info['dept'] if info else None

    def get_ad_title(self, obj):
        info = self._get_ad_info(obj)
        return info['title'] if info else None

class RiskEventSerializer(serializers.ModelSerializer):
    class Meta:
        from dashboard.models import RiskEvent
        model = RiskEvent
        fields = '__all__'

class UserRiskScoreSerializer(serializers.ModelSerializer):
    events = RiskEventSerializer(many=True, read_only=True)
    
    class Meta:
        from dashboard.models import UserRiskScore
        model = UserRiskScore
        fields = [
            'id', 'username', 'current_score', 'risk_level', 
            'last_calculated', 'trend', 'events'
        ]
