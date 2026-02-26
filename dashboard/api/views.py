from rest_framework import viewsets, permissions, status
from rest_framework.response import Response
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from django.db.models import Sum, Count, Max, Q, Subquery, OuterRef, F, Case, When, Value, IntegerField
from django.db import models
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
    UserRiskScoreDetailSerializer,
    VPNLogSerializer, 
    RiskEventSerializer
)

class DashboardPagination(PageNumberPagination):
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200

class VPNLogViewSet(viewsets.ModelViewSet):
    queryset = VPNLog.objects.all()
    serializer_class = VPNLogSerializer
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        """Aggregated list of VPN users with performance optimization"""
        from dashboard.models import DashboardMetric
        
        # Apply filters from query params
        user_q = request.query_params.get('user_q')
        title_q = request.query_params.get('title_q')
        dept_q = request.query_params.get('dept_q')
        date_str = request.query_params.get('date')

        # 0. Initial Queryset for base filtering
        base_qs = VPNLog.objects.filter(
            Q(raw_data__tunneltype__icontains='ssl') | 
            Q(raw_data__vpntype__icontains='ssl') |
            Q(raw_data__service__icontains='SSL')
        )
        
        if user_q:
            base_qs = base_qs.filter(Q(user__icontains=user_q) | Q(ad_display_name__icontains=user_q))
        if title_q:
            base_qs = base_qs.filter(ad_title__icontains=title_q)
        if dept_q:
            base_qs = base_qs.filter(ad_department__icontains=dept_q)
        if date_str:
            try:
                filter_date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
                base_qs = base_qs.filter(start_date=filter_date)
            except ValueError:
                pass

        # Optimized aggregation: grouping by user is still needed for the table
        # We use select_related or prefetch for any related data if needed
        # (VPNLog doesn't have many foreign keys in this list view)
        
        latest_log_qs = VPNLog.objects.filter(user=OuterRef('user')).order_by('-start_time')
        
        qs = base_qs.values(
            'user', 
            'ad_display_name', 
            'ad_department', 
            'ad_title'
        ).annotate(
            total_connections=Count('id'),
            total_duration=Sum('duration'),
            total_volume=Sum(F('bandwidth_in') + F('bandwidth_out')),
            last_connection=Max('start_time'),
            latest_source_ip=Subquery(latest_log_qs.values('source_ip')[:1]),
            latest_city=Subquery(latest_log_qs.values('city')[:1]),
            latest_country=Subquery(latest_log_qs.values('country_name')[:1]),
            latest_country_code=Subquery(latest_log_qs.values('country_code')[:1]),
            latest_status=Subquery(latest_log_qs.values('status')[:1]),
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

        ordering_param = request.query_params.get('ordering', '-last_connection')
        sort_map = {
            'user': 'user', '-user': '-user',
            'volume': 'total_volume', '-volume': '-total_volume',
            'duration': 'total_duration', '-duration': '-total_duration',
            'connections': 'total_connections', '-connections': '-total_connections',
            'last_connection': 'last_connection', '-last_connection': '-last_connection',
            'title': 'ad_title', '-title': '-ad_title',
            'dept': 'ad_department', '-dept': '-ad_department'
        }
        secondary_sort = sort_map.get(ordering_param, '-last_connection')
        qs = qs.order_by('-online_priority', secondary_sort)

        serializer = VPNLogAggregatedSerializer(qs, many=True)
        return Response({
            'logs': serializer.data,
            'server_time': datetime.datetime.now().isoformat()
        })

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Global VPN stats using DashboardMetric"""
        from dashboard.models import DashboardMetric
        from django.db.models import Sum
        
        metrics_qs = DashboardMetric.objects.filter(group='vpn')
        total_connections = metrics_qs.filter(metric_name='total_connections', key='all').aggregate(s=Sum('count'))['s'] or 0
        total_volume = metrics_qs.filter(metric_name='total_volume', key='all').aggregate(s=Sum('volume'))['s'] or 0
        suspicious_count = metrics_qs.filter(metric_name='suspicious_connections', key='all').aggregate(s=Sum('count'))['s'] or 0

        return Response({
            'total_connections': total_connections,
            'total_volume': total_volume,
            'suspicious_count': suspicious_count
        })



    @action(detail=False, methods=['get'])
    def history(self, request):
        """Get connection history for a specific user"""
        user = request.query_params.get('user')
        if not user:
            return Response({'error': 'User parameter required'}, status=status.HTTP_400_BAD_REQUEST)
            
        logs = VPNLog.objects.filter(user__iexact=user).order_by('-start_time')[:50]
        serializer = VPNLogSerializer(logs, many=True)
        return Response({'logs': serializer.data})

class VPNFailureViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for VPN Failures — com limite de 500 registros mais recentes"""
    serializer_class = VPNFailureSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = DashboardPagination

    def get_queryset(self):
        # Limitar a 500 registros mais recentes (se for remover, usar paginação segura)
        queryset = VPNFailure.objects.all().order_by('-timestamp')
        user = self.request.query_params.get('user')
        ip = self.request.query_params.get('ip')
        start_date = self.request.query_params.get('start_date')
        
        if user:
            queryset = queryset.filter(user__icontains=user)
        if ip:
            queryset = queryset.filter(source_ip__icontains=ip)
        if start_date:
            queryset = queryset.filter(timestamp__date=start_date)
        return queryset

class UserRiskScoreViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet para Score de Risco — serializer leve na lista, completo no detalhe"""
    serializer_class = UserRiskScoreSerializer
    permission_classes = [permissions.IsAuthenticated]
    pagination_class = DashboardPagination

    def get_serializer_class(self):
        # Usa serializer completo (com events) apenas no detalhe individual
        if self.action == 'retrieve':
            return UserRiskScoreDetailSerializer
        return UserRiskScoreSerializer

    def get_queryset(self):
        from dashboard.models import UserRiskScore, RiskEvent
        from django.db.models import Sum, Q

        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')

        queryset = UserRiskScore.objects.all()

        if start_date or end_date:
            # Filtro dinâmico por período baseado nos eventos
            event_filter = Q()
            if start_date:
                event_filter &= Q(events__timestamp__date__gte=start_date)
            if end_date:
                event_filter &= Q(events__timestamp__date__lte=end_date)
            
            queryset = queryset.annotate(
                period_score=Sum('events__weight_added', filter=event_filter)
            ).filter(period_score__gt=0).order_by('-period_score')
        else:
            # Comportamento padrão: usa o score pré-calculado
            queryset = queryset.filter(current_score__gt=0).order_by('-current_score')

        # Filtros adicionais
        user = self.request.query_params.get('user')
        if user:
            queryset = queryset.filter(username__icontains=user)

        level = self.request.query_params.get('level')
        if level:
            queryset = queryset.filter(risk_level__iexact=level)

        if self.action == 'retrieve':
            queryset = queryset.prefetch_related('events')

        return queryset

    def list(self, request, *args, **kwargs):
        # Override list to inject period_score into current_score for the serializer if filtering by date
        queryset = self.filter_queryset(self.get_queryset())
        
        page = self.paginate_queryset(queryset)
        if page is not None:
            serializer = self.get_serializer(page, many=True)
            data = serializer.data
            # Injetar period_score se existir
            if request.query_params.get('start_date') or request.query_params.get('end_date'):
                for idx, obj in enumerate(page):
                    if hasattr(obj, 'period_score'):
                        data[idx]['current_score'] = obj.period_score or 0
            return self.get_paginated_response(data)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)
