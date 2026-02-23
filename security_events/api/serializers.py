from urllib.parse import unquote
import json
from rest_framework import serializers
from security_events.models import SecurityEvent, ADAuthEvent


class SecurityEventSerializer(serializers.ModelSerializer):
    """Serializer for SecurityEvent model with all fields"""
    
    # Add display fields for better frontend rendering
    severity_display = serializers.CharField(source='get_severity_display', read_only=True)
    action_display = serializers.SerializerMethodField()
    details = serializers.SerializerMethodField()
    
    class Meta:
        model = SecurityEvent
        fields = [
            'id', 'timestamp', 'event_type', 'severity', 'severity_display',
            'username', 'src_ip', 'dst_ip', 'src_port', 'dst_port', 
            'src_country', 'dst_country',
            'url', 'category', 'action', 'action_display',
            'attack_name', 'attack_id', 'ad_display_name', 'ad_title', 'user_department',
            'cve',
            'virus_name', 'file_name', 'file_hash',
            'app_name', 'app_category', 'app_risk', 'bytes_in', 'bytes_out',
            'details'
        ]
    
    def get_action_display(self, obj):
        """Return user-friendly action display"""
        if obj.action in ['block', 'blocked']:
            return 'Bloqueado'
        elif obj.action in ['passthrough', 'pass']:
            return 'Permitido'
        return obj.action or 'N/A'

    def get_details(self, obj):
        """Extract additional details from raw_log"""
        if not obj.raw_log:
            return {}
            
        try:
            # Handle if raw_log is string or dict (though model says TextField)
            data = json.loads(obj.raw_log) if isinstance(obj.raw_log, str) else obj.raw_log
            
            # Additional parse if double encoded (common in some fields)
            if isinstance(data, str):
                 try: data = json.loads(data)
                 except: pass

            if not isinstance(data, dict):
                return {}

            return {
                'msg': unquote(data.get('msg', '')),
                'direction': data.get('direction', ''),
                'profile': data.get('profile', ''),
                'ref': data.get('ref', ''),
                'policyid': data.get('policyid', '')
            }
        except Exception:
            return {}

        # Basic extraction for all types
        details = {
            'msg': unquote(data.get('msg', '')),
            'direction': data.get('direction', ''),
            'profile': data.get('profile', ''),
            'ref': data.get('ref', ''),
            'policyid': data.get('policyid', '')
        }

        # IPS Specific Enrichment
        if obj.event_type == 'ips':
            details.update({
                'srcintf': data.get('srcintf', ''),
                'dstintf': data.get('dstintf', ''),
                'service': data.get('service', ''),
                'attack': data.get('attack', ''),
                'severity_score': data.get('severity', ''),  # Raw numeric severity if avail
                'incidentserialno': data.get('incidentserialno', ''),
                'raw_dump': json.dumps(data, indent=2)  # For advanced view
            })
            
        return details


class ADAuthEventSerializer(serializers.ModelSerializer):
    """Serializer for ADAuthEvent model"""
    
    status_display = serializers.CharField(source='get_status_display', read_only=True)
    
    class Meta:
        model = ADAuthEvent
        fields = [
            'id', 'username', 'workstation', 'src_ip', 'status', 'status_display',
            'event_id', 'message', 'ad_department', 'ad_title', 'ad_display_name',
            'timestamp', 'created_at'
        ]

# =========================================================
# RADAR AD (Postura Ldap)
# =========================================================

from security_events.models import ADUser, ADGroup, ADRiskSnapshot, ADMemberOf

class ADGroupSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADGroup
        fields = ['id', 'cn', 'sid', 'is_privileged', 'weight', 'last_seen']

class ADUserSerializer(serializers.ModelSerializer):
    groups = serializers.SerializerMethodField()
    
    class Meta:
        model = ADUser
        fields = [
            'id', 'username', 'sid', 'display_name', 'department', 'title',
            'last_logon', 'pwd_last_set', 'is_inactive', 'is_disabled', 
            'is_privileged', 'last_seen', 'groups'
        ]

    def get_groups(self, obj):
        memberships = obj.group_memberships.all()
        return [m.group.cn for m in memberships if m.group]


class ADRiskSnapshotSerializer(serializers.ModelSerializer):
    class Meta:
        model = ADRiskSnapshot
        fields = '__all__'

