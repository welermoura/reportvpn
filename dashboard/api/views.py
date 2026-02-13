from rest_framework import viewsets, permissions
from rest_framework.response import Response
from django.db.models import Sum, Count, Max, Q, Subquery, OuterRef
from vpn_logs.models import VPNLog
from .serializers import VPNLogAggregatedSerializer
import datetime

class VPNLogViewSet(viewsets.ViewSet):
    permission_classes = [permissions.IsAuthenticated]

    def list(self, request):
        queryset = VPNLog.objects.all()

        # Filters
        user_q = request.query_params.get('user_q')
        if user_q:
            queryset = queryset.filter(
                Q(user__icontains=user_q) | Q(ad_display_name__icontains=user_q)
            )

        title_q = request.query_params.get('title_q')
        if title_q:
            queryset = queryset.filter(ad_title__icontains=title_q)

        dept_q = request.query_params.get('dept_q')
        if dept_q:
            queryset = queryset.filter(ad_department__icontains=dept_q)

        date_str = request.query_params.get('date')
        if date_str:
            try:
                filter_date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
                queryset = queryset.filter(start_date=filter_date)
            except ValueError:
                pass

        # Aggregation Logic
        latest_log_qs = VPNLog.objects.filter(user=OuterRef('user')).order_by('-start_time')
        
        qs = queryset.order_by().values(
            'user', 
            'ad_display_name', 
            'ad_department', 
            'ad_title'
        ).annotate(
            total_connections=Count('id'),
            total_duration=Sum('duration'),
            total_volume=Sum('bandwidth_in') + Sum('bandwidth_out'),
            last_connection=Max('start_time'),
            latest_source_ip=Subquery(latest_log_qs.values('source_ip')[:1]),
            latest_city=Subquery(latest_log_qs.values('city')[:1]),
            latest_country=Subquery(latest_log_qs.values('country_name')[:1]),
            latest_country_code=Subquery(latest_log_qs.values('country_code')[:1])
        )

        # Ordering
        ordering = request.query_params.get('ordering', '-last_connection')
        # Map fields if necessary
        if ordering in ['volume', '-volume']:
            field = 'total_volume'
            prefix = '-' if ordering == 'volume' else ''
            qs = qs.order_by(f'{prefix}{field}')
        elif ordering in ['duration', '-duration']:
            field = 'total_duration'
            prefix = '-' if ordering == 'duration' else ''
            qs = qs.order_by(f'{prefix}{field}')
        elif ordering in ['start_time', '-start_time']:
            field = 'last_connection'
            prefix = '-' if ordering == 'start_time' else ''
            qs = qs.order_by(f'{prefix}{field}')
        else:
            qs = qs.order_by(ordering)

        serializer = VPNLogAggregatedSerializer(qs, many=True)
        return Response(serializer.data)

    from rest_framework.decorators import action
    @action(detail=False, methods=['get'])
    def history(self, request):
        """Get connection history for a specific user"""
        user = request.query_params.get('user')
        if not user:
            return Response({'error': 'User parameter required'}, status=400)
            
        # Buscar últimos 50 logs do usuário (Case insensitive)
        logs = VPNLog.objects.filter(user__iexact=user).order_by('-start_time')[:50]
        
        from .serializers import VPNLogSerializer
        serializer = VPNLogSerializer(logs, many=True)
        return Response(serializer.data)

class VPNFailureViewSet(viewsets.ReadOnlyModelViewSet):
    """ViewSet for VPN Failures"""
    from vpn_logs.models import VPNFailure
    from .serializers import VPNFailureSerializer
    
    queryset = VPNFailure.objects.all().order_by('-timestamp')
    serializer_class = VPNFailureSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_queryset(self):
        queryset = super().get_queryset()
        user = self.request.query_params.get('user')
        if user:
            queryset = queryset.filter(user__icontains=user)
            
        ip = self.request.query_params.get('ip')
        if ip:
            queryset = queryset.filter(source_ip=ip)
            
        return queryset
