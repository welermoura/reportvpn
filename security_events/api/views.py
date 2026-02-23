from rest_framework import viewsets, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count
from security_events.models import SecurityEvent, ADAuthEvent
from .serializers import SecurityEventSerializer, ADAuthEventSerializer
from django.utils import timezone


class SecurityEventPagination(PageNumberPagination):
    """Custom pagination for security events"""
    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200


class WebFilterViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for webfilter security events
    
    Supports filtering by:
    - username: Filter by username or AD display name
    - category: Filter by event category
    - action: Filter by action (blocked, passthrough, etc.)
    - url: Search in URL field
    - department: Filter by user department
    """
    serializer_class = SecurityEventSerializer
    pagination_class = SecurityEventPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    
    # Define filterable fields
    filterset_fields = {
        'category': ['exact'],
        'action': ['exact'],
        'severity': ['exact'],
        'user_department': ['exact', 'icontains'],
    }
    
    # Define searchable fields
    search_fields = ['username', 'ad_display_name', 'url', 'category']
    
    # Define orderable fields
    ordering_fields = ['timestamp', 'severity', 'category']
    ordering = ['-timestamp']  # Default ordering

    
    def get_queryset(self):
        """Return webfilter events only"""
        queryset = SecurityEvent.objects.filter(event_type='webfilter')
        
        # Additional custom filters
        username_q = self.request.query_params.get('username', None)
        url_q = self.request.query_params.get('url', None)
        department_q = self.request.query_params.get('department', None)
        
        if username_q:
            queryset = queryset.filter(
                username__icontains=username_q
            ) | queryset.filter(
                ad_display_name__icontains=username_q
            )
        
        if url_q:
            queryset = queryset.filter(url__icontains=url_q)
        
        if department_q:
            queryset = queryset.filter(user_department__icontains=department_q)

        # Date filtering
        start_date = self.request.query_params.get('start_date', None)
        end_date = self.request.query_params.get('end_date', None)

        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            # Append max time to include the entire end date
            queryset = queryset.filter(timestamp__lte=f"{end_date} 23:59:59")
        
        return queryset.select_related().order_by('-timestamp')

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Return statistics for dashboard charts"""
        # Base webfilter queryset with all filters applied
        queryset = self.filter_queryset(self.get_queryset())
        
        # Totals
        total_events = queryset.count()
        blocked_events = queryset.filter(action__in=['block', 'blocked']).count()
        
        # Top Categories (Blocked)
        top_categories = queryset.filter(
            action__in=['block', 'blocked']
        ).values('category').annotate(
            count=Count('id')
        ).order_by('-count')[:20]
        
        # Top Sites (Blocked)
        # Extract domain from URL or use as is if simple
        top_sites = queryset.filter(
            action__in=['block', 'blocked']
        ).values('url').annotate(
            count=Count('id')
        ).order_by('-count')[:20]
        
        return Response({
            'total_events': total_events,
            'blocked_events': blocked_events,
            'top_categories': list(top_categories),
            'top_sites': list(top_sites)
        })

    @action(detail=False, methods=['get'])
    def categories(self, request):
        """Return list of distinct categories for filtering"""
        categories = self.get_queryset().order_by('category').values_list('category', flat=True).distinct()
        # Filter out empty or None
        categories = [c for c in categories if c]
        return Response(categories)


class IPSViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for IPS security events
    """
    serializer_class = SecurityEventSerializer
    pagination_class = SecurityEventPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    
    # Define filterable fields
    filterset_fields = {
        'severity': ['exact'],
        'action': ['exact'],
        'src_country': ['exact'],
    }
    
    # Define searchable fields
    search_fields = ['attack_name', 'cve', 'src_ip', 'dst_ip', 'username']
    
    # Define orderable fields
    ordering_fields = ['timestamp', 'severity', 'attack_name']
    ordering = ['-timestamp']

    def get_queryset(self):
        """Return IPS events only"""
        queryset = SecurityEvent.objects.filter(event_type='ips')
        
        # Date filtering
        start_date = self.request.query_params.get('start_date', None)
        end_date = self.request.query_params.get('end_date', None)

        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=f"{end_date} 23:59:59")
        
        return queryset.select_related().order_by('-timestamp')

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Return statistics for dashboard charts"""
        from django.db.models import Case, When, IntegerField
        queryset = self.filter_queryset(self.get_queryset())
        
        # Uma única query agregada para evitar race condition (Críticos > Total)
        agg = queryset.aggregate(
            total_events=Count('id'),
            critical_events=Count(Case(When(severity='critical', then=1), output_field=IntegerField())),
            high_events=Count(Case(When(severity='high', then=1), output_field=IntegerField())),
        )
        
        # Top Attacks
        top_attacks = queryset.values('attack_name').annotate(
            count=Count('id')
        ).order_by('-count')[:20]
        
        # Top Sources
        top_sources = queryset.exclude(src_ip='0.0.0.0').values('src_ip').annotate(
            count=Count('id')
        ).order_by('-count')[:20]
        
        # Severity Distribution
        severity_dist = queryset.values('severity').annotate(
            count=Count('id')
        ).order_by('-count')
        
        return Response({
            'total_events': agg['total_events'],
            'critical_events': agg['critical_events'],
            'high_events': agg['high_events'],
            'top_attacks': list(top_attacks),
            'top_sources': list(top_sources),
            'severity_dist': list(severity_dist)
        })



class AntivirusViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for Antivirus events
    """
    serializer_class = SecurityEventSerializer
    pagination_class = SecurityEventPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['severity', 'action', 'username', 'src_country']
    search_fields = ['virus_name', 'file_name', 'file_hash', 'src_ip', 'username']
    ordering_fields = ['timestamp', 'severity']
    ordering = ['-timestamp']

    def get_queryset(self):
        queryset = SecurityEvent.objects.filter(event_type='antivirus')
        
        # Date filtering
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=f"{end_date} 23:59:59")
            
        return queryset.select_related().order_by('-timestamp')

    @action(detail=False, methods=['get'])
    def stats(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        
        total_events = queryset.count()
        critical_events = queryset.filter(severity='critical').count()
        high_events = queryset.filter(severity='high').count()
        
        # Top Viruses
        top_viruses = queryset.values('virus_name').annotate(
             count=Count('id')
        ).order_by('-count')[:20]

        # Top Users
        top_users = queryset.exclude(username='').values('username').annotate(
            count=Count('id')
        ).order_by('-count')[:20]

        # Severity Distribution
        severity_dist = queryset.values('severity').annotate(
            count=Count('id')
        ).order_by('-count')

        return Response({
            'total_events': total_events,
            'critical_events': critical_events,
            'high_events': high_events,
            'top_viruses': list(top_viruses),
            'top_users': list(top_users),
            'severity_dist': list(severity_dist)
        })


class AppControlViewSet(viewsets.ReadOnlyModelViewSet):
    """
    API endpoint for App Control events
    """
    serializer_class = SecurityEventSerializer
    pagination_class = SecurityEventPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['action', 'app_category', 'app_risk', 'username']
    search_fields = ['app_name', 'username', 'src_ip', 'dst_ip']
    ordering_fields = ['timestamp', 'bytes_total']
    ordering = ['-timestamp']

    def get_queryset(self):
        queryset = SecurityEvent.objects.filter(event_type='app-control')
        
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=f"{end_date} 23:59:59")
            
        return queryset.select_related().order_by('-timestamp')

    @action(detail=False, methods=['get'])
    def stats(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        
        total_events = queryset.count()
        
        # Top Apps
        top_apps = queryset.exclude(app_name='').values('app_name').annotate(
             count=Count('id')
        ).order_by('-count')[:20]

        # Top Users
        top_users = queryset.exclude(username='').values('username').annotate(
            count=Count('id')
        ).order_by('-count')[:20]

        # Top Categories
        top_categories = queryset.exclude(app_category='').values('app_category').annotate(
            count=Count('id')
        ).order_by('-count')[:20]

        return Response({
            'total_events': total_events,
            'top_apps': list(top_apps),
            'top_users': list(top_users),
            'top_categories': list(top_categories)
        })

class ADAuthEventViewSet(viewsets.ModelViewSet):
    """
    API endpoint for AD Authentication events
    """
    serializer_class = ADAuthEventSerializer
    pagination_class = SecurityEventPagination
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['status', 'event_id', 'username']
    search_fields = ['username', 'workstation', 'src_ip', 'message']
    ordering_fields = ['timestamp']
    ordering = ['-timestamp']

    def get_queryset(self):
        queryset = ADAuthEvent.objects.all()
        
        start_date = self.request.query_params.get('start_date')
        end_date = self.request.query_params.get('end_date')
        
        if start_date:
            queryset = queryset.filter(timestamp__gte=start_date)
        if end_date:
            queryset = queryset.filter(timestamp__lte=f"{end_date} 23:59:59")
            
        return queryset.order_by('-timestamp')

    @action(detail=False, methods=['get'])
    def stats(self, request):
        queryset = self.filter_queryset(self.get_queryset())
        
        total_events = queryset.count()
        failed_logins = queryset.filter(status='failed').count()
        locked_accounts = queryset.filter(status='locked').count()
        
        # Top Users with Failed Logins
        top_failed_users = queryset.filter(status='failed').exclude(username='').values('username').annotate(
             count=Count('id')
        ).order_by('-count')[:20]

        # Top Workstations with failed logins
        top_failed_workstations = queryset.filter(status='failed').exclude(workstation='').values('workstation').annotate(
            count=Count('id')
        ).order_by('-count')[:20]

        # Heatmap Data (Logins por hora)
        # Extrair a hora agregada e contar - para simplicidade usaremos uma query agregada básica
        # Se for no sqlite pode dar divergência do postgres de extração de hora, então faremos via Python se necessário,
        # ou count básico. 
        # Optando por enviar os eventos agrupados para o frontend calcular o Heatmap (mais leve)
        # limitando para heatmap events às últimas 24/48h por exemplo:
        recent_events = list(queryset.order_by('-timestamp')[:500].values('timestamp', 'status'))


        return Response({
            'total_events': total_events,
            'failed_logins': failed_logins,
            'locked_accounts': locked_accounts,
            'top_failed_users': list(top_failed_users),
            'top_failed_workstations': list(top_failed_workstations),
            'recent_auth_events': recent_events
        })
        
    @action(detail=False, methods=['post'])
    def ingest(self, request):
        """
        Recebe eventos de logon (via script de Powershell/WMI/Syslog)
        Payload esperado: list de dicts ou dict unico
        """
        data = request.data
        if not isinstance(data, list):
            data = [data]
            
        created_count = 0
        for item in data:
            serializer = self.get_serializer(data=item)
            if serializer.is_valid():
                serializer.save()
                created_count += 1
                
        return Response({"status": "Success", "created": created_count}, status=201)

# =========================================================
# RADAR AD (Auditoria de Postura LDAP - Módulo 3 Novo)
# =========================================================

from .serializers import ADUserSerializer, ADGroupSerializer, ADRiskSnapshotSerializer
from security_events.models import ADUser, ADGroup, ADRiskSnapshot
from .radar_scanner import RadarScanner
from rest_framework import status

class RadarADViewSet(viewsets.ViewSet):
    """
    API endpoint for Active Directory Posture/Risk (Radar AD)
    """

    @action(detail=False, methods=['get'])
    def stats(self, request):
        """Retorna a visão geral atual do Risco (Baseado no último Snapshot)"""
        last_snap = ADRiskSnapshot.objects.first()
        
        if not last_snap:
            return Response({
                "has_data": False,
                "message": "Nenhuma varredura do Radar AD foi concluída ainda. Clique em Iniciar Varredura."
            })
            
        return Response({
            "has_data": True,
            "last_scan": last_snap.timestamp,
            "total_users": last_snap.total_users,
            "total_groups": last_snap.total_groups,
            "privileged_users": last_snap.privileged_users_count,
            "inactive_privileged": last_snap.inactive_privileged_count,
            "disabled_privileged": last_snap.disabled_privileged_count,
            "findings_data": last_snap.findings_data or [],
            "direct_members_data": last_snap.direct_members_data or {},
            "inactive_users_data": last_snap.inactive_users_data or []
        })

    @action(detail=False, methods=['post'])
    def scan(self, request):
        """Aciona a varredura LDAP através de um Background Job (Celery)"""
        try:
            from security_events.tasks import run_ad_radar_scan_task
            
            # Dispara a varredura assincrona
            task = run_ad_radar_scan_task.delay()
            
            return Response(
                {
                    "status": "Accepted", 
                    "message": "A varredura do AD foi iniciada em segundo plano.",
                    "task_id": task.id
                }, 
                status=status.HTTP_202_ACCEPTED
            )
        except Exception as e:
             return Response({"status": "Error", "message": f"Erro despachar Task Celery: {str(e)}"}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

