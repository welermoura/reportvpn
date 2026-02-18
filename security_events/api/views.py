from rest_framework import viewsets, filters
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.pagination import PageNumberPagination
from django_filters.rest_framework import DjangoFilterBackend
from django.db.models import Count
from security_events.models import SecurityEvent
from .serializers import SecurityEventSerializer


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
        ).order_by('-count')[:5]
        
        # Top Sites (Blocked)
        # Extract domain from URL or use as is if simple
        top_sites = queryset.filter(
            action__in=['block', 'blocked']
        ).values('url').annotate(
            count=Count('id')
        ).order_by('-count')[:5]
        
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
        queryset = self.filter_queryset(self.get_queryset())
        
        # Totals
        total_events = queryset.count()
        critical_events = queryset.filter(severity='critical').count()
        high_events = queryset.filter(severity='high').count()
        
        # Top Attacks
        top_attacks = queryset.values('attack_name').annotate(
            count=Count('id')
        ).order_by('-count')[:5]
        
        # Top Sources
        top_sources = queryset.values('src_ip').annotate(
            count=Count('id')
        ).order_by('-count')[:5]
        
        # Severity Distribution
        severity_dist = queryset.values('severity').annotate(
            count=Count('id')
        ).order_by('-count')
        
        return Response({
            'total_events': total_events,
            'critical_events': critical_events,
            'high_events': high_events,
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
        ).order_by('-count')[:5]

        # Top Users
        top_users = queryset.exclude(username='').values('username').annotate(
            count=Count('id')
        ).order_by('-count')[:5]

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
