from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from django.db.models import Sum, Count, Max, Q, Subquery, OuterRef
from django.http import JsonResponse
import datetime

# Explicit imports to avoid any shadowing or module resolution issues
try:
    from dashboard.models import UserRiskScore, RiskEvent
except ImportError:
    from ..models import UserRiskScore, RiskEvent

from vpn_logs.models import VPNLog, VPNFailure
from .serializers import (
    VPNLogAggregatedSerializer, 
    VPNFailureSerializer, 
    UserRiskScoreSerializer, 
    VPNLogSerializer, 
    RiskEventSerializer
)

class VPNLogViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    
    
    def list(self, request):
        queryset = self.get_queryset()
        queryset = self.filter_queryset(queryset)
        
        date_str = request.query_params.get('date')
        if date_str:
            try:
                filter_date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
                queryset = queryset.filter(start_date=filter_date)
            except ValueError:
                pass

        # 1. Latest Log Subquery
        latest_log_qs = VPNLog.objects.filter(user=OuterRef('user')).order_by('-start_time')
        
        # 2. Main aggregation query
        # We group by user and other info, then annotate stats and latest info
        qs = VPNLog.objects.values(
            'user', 
            'ad_display_name', 
            'ad_department', 
            'ad_title'
        ).annotate(
            total_connections=Count('id'),
            total_duration=Sum('duration'),
            total_volume=Sum(models.F('bandwidth_in') + models.F('bandwidth_out')),
            last_connection=Max('start_time'),
            latest_source_ip=Subquery(latest_log_qs.values('source_ip')[:1]),
            latest_city=Subquery(latest_log_qs.values('city')[:1]),
            latest_country=Subquery(latest_log_qs.values('country_name')[:1]),
            latest_country_code=Subquery(latest_log_qs.values('country_code')[:1]),
            latest_status=Subquery(latest_log_qs.values('status')[:1]),
            # Calculate online priority (1 for active, 0 for others)
            online_priority=Subquery(
                VPNLog.objects.filter(user=OuterRef('user'))
                .order_by('-start_time')
                .annotate(
                    p=Case(
                        When(status__in=['active', 'tunnel-up'], then=Value(1)),
                        default=Value(0),
                        output_field=IntegerField()
                    )
                ).values('p')[:1]
            )
        )

        # 3. Handle Ordering
        ordering_param = request.query_params.get('ordering', '-last_connection')
        
        sort_map = {
            'user': 'user',
            '-user': '-user',
            'volume': 'total_volume',
            '-volume': '-total_volume',
            'duration': 'total_duration',
            '-duration': '-total_duration',
            'connections': 'total_connections',
            '-connections': '-total_connections',
            'last_connection': 'last_connection',
            '-last_connection': '-last_connection',
            'title': 'ad_title',
            '-title': '-ad_title',
            'dept': 'ad_department',
            '-dept': '-ad_department'
        }
        
        secondary_sort = sort_map.get(ordering_param, '-last_connection')

        # 4. Apply Final Ordering: Always Online Priority first, then user's choice
        qs = qs.order_by('-online_priority', secondary_sort)

        serializer = VPNLogAggregatedSerializer(qs, many=True)
        return Response({
            'logs': serializer.data,
            'server_time': datetime.datetime.now().isoformat()
        })



    @action(detail=False, methods=['get'])
    def history(self, request):
        """Get connection history for a specific user"""
        user = request.query_params.get('user')
        if not user:
            return Response({'error': 'User parameter required'}, status=status.HTTP_400_BAD_REQUEST)
            
        logs = VPNLog.objects.filter(user__iexact=user).order_by('-start_time')[:50]
        serializer = VPNLogSerializer(logs, many=True)
        return Response(serializer.data)

class VPNFailureViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for VPN Failures"""
    queryset = VPNFailure.objects.all().order_by('-timestamp')
    serializer_class = VPNFailureSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.query_params.get('user')
        if user:
            queryset = queryset.filter(user__icontains=user)
        return queryset

class UserRiskScoreViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for User Risk Scores"""
    # Use explicit reference to the model to avoid any shadowing
    queryset = UserRiskScore.objects.all().prefetch_related('events').order_by('-current_score')
    serializer_class = UserRiskScoreSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        # Local import as a last resort if global fails
        from dashboard.models import UserRiskScore
        queryset = UserRiskScore.objects.all().prefetch_related('events').order_by('-current_score')
        
        user = self.request.query_params.get('user')
        if user:
            queryset = queryset.filter(username__icontains=user)
        
        level = self.request.query_params.get('level')
        if level:
            queryset = queryset.filter(risk_level__iexact=level)
            
        return queryset
