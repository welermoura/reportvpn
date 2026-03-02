"""Security Events Views"""
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils import timezone
from datetime import timedelta
from .models import SecurityEvent
import csv
import json
from django.http import HttpResponse, JsonResponse
from django.template.loader import get_template
from io import BytesIO
from dashboard.utils import export_to_xlsx


@login_required
def index(request):
    """Main security events dashboard"""
    # Get date range (last 7 days by default)
    days = int(request.GET.get('days', 7))
    start_date = timezone.now() - timedelta(days=days)
    
    # Get filter parameters
    event_type = request.GET.get('event_type', '')
    severity = request.GET.get('severity', '')
    search = request.GET.get('search', '')
    
    # Base queryset
    events = SecurityEvent.objects.filter(timestamp__gte=start_date)
    
    # Apply filters
    if event_type:
        events = events.filter(event_type=event_type)
    if severity:
        events = events.filter(severity=severity)
    if search:
        events = events.filter(
            Q(src_ip__icontains=search) |
            Q(dst_ip__icontains=search) |
            Q(username__icontains=search) |
            Q(attack_name__icontains=search) |
            Q(virus_name__icontains=search) |
            Q(url__icontains=search)
        )
    
    # Statistics
    total_events = events.count()
    critical_events = events.filter(severity='critical').count()
    high_events = events.filter(severity='high').count()
    
    # Brute Force Stats
    from vpn_logs.models import VPNFailure
    bruteforce_count = VPNFailure.objects.filter(timestamp__gte=start_date).count()
    
    # Top source countries
    top_countries = events.order_by().exclude(src_country='').values('src_country').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Severity distribution for chart
    severity_dist = events.order_by().values('severity').annotate(count=Count('id'))
    
    # Pagination
    paginator = Paginator(events.order_by('-timestamp'), 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'events': page_obj,
        'stats': { # Nested stats dict for cleaner template access
            'critical': critical_events,
            'ips': events.filter(event_type='ips').count(),
            'webfilter': events.filter(event_type='webfilter').count(),
            'antivirus': events.filter(event_type='antivirus').count(),
            'bruteforce': bruteforce_count
        },
        'total_events': total_events,
        'critical_events': critical_events,
        'high_events': high_events,
        'events_by_type': list(events.order_by().values('event_type').annotate(count=Count('id')).order_by()),
        'top_sources': list(events.order_by().values('src_ip').annotate(count=Count('id')).order_by('-count')[:10]),
        'top_destinations': list(events.order_by().values('dst_ip').annotate(count=Count('id')).order_by('-count')[:10]),
        'top_countries': list(events.order_by().values('src_country').annotate(count=Count('id')).order_by('-count')[:5]),
        'severity_dist': list(events.order_by().values('severity').annotate(count=Count('id')).order_by()),
        'days': days,
        'event_type': event_type,
        'severity': severity,
        'search': search,
    }
    
    return render(request, 'security_events/index.html', context)


@login_required
def ips_dashboard(request):
    """Old IPS dashboard - Kept for backup"""
    # ... existing code ...
    pass 

@login_required
def ips_react_dashboard(request):
    """New React-based IPS Dashboard"""
    return render(request, 'security_events/ips_react.html')

@login_required
def antivirus_react_dashboard(request):
    """New React-based Antivirus Dashboard"""
    return render(request, 'security_events/antivirus_react.html')
    # Get date range
    days = int(request.GET.get('days', 7))
    start_date = timezone.now() - timedelta(days=days)
    
    # Get filter parameters
    severity = request.GET.get('severity', '')
    search = request.GET.get('search', '')
    
    # Base queryset - only IPS events
    events = SecurityEvent.objects.filter(
        event_type='ips',
        timestamp__gte=start_date
    )
    
    # Apply filters
    if severity:
        events = events.filter(severity=severity)
    if search:
        events = events.filter(
            Q(src_ip__icontains=search) |
            Q(dst_ip__icontains=search) |
            Q(attack_name__icontains=search) |
            Q(cve__icontains=search)
        )
    
    # Statistics
    total_attacks = events.count()
    critical_attacks = events.filter(severity='critical').count()
    
    # Top attack signatures
    top_attacks = events.order_by().values('attack_name').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Top attackers
    top_attackers = events.order_by().values('src_ip', 'src_country').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Top targets
    top_targets = events.order_by().values('dst_ip').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Attacks by severity
    attacks_by_severity = list(events.order_by().values('severity').annotate(count=Count('id')))
    
    # Attacks over time (last 7/30 days)
    attacks_over_time = [
        {'date': str(d['date']), 'count': d['count']}
        for d in events.order_by().values('date').annotate(count=Count('id')).order_by('date')
    ]
    
    # Pagination
    paginator = Paginator(events.order_by('-timestamp'), 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'events': page_obj,
        'total_attacks': total_attacks,
        'critical_attacks': critical_attacks,
        'top_attacks': list(events.order_by().values('attack_name').annotate(count=Count('id')).order_by('-count')[:10]),
        'top_attackers': list(events.order_by().values('src_ip', 'src_country').annotate(count=Count('id')).order_by('-count')[:10]),
        'top_targets': list(events.order_by().values('dst_ip').annotate(count=Count('id')).order_by('-count')[:10]),
        'attacks_by_severity': list(events.order_by().values('severity').annotate(count=Count('id'))),
        'attacks_over_time': attacks_over_time,
        'days': days,
        'severity': severity,
        'search': search,
    }
    
    return render(request, 'security_events/ips.html', context)


@login_required
def antivirus_dashboard(request):
    """Antivirus/Malware dashboard"""
    # Get date range
    days = int(request.GET.get('days', 7))
    start_date = timezone.now() - timedelta(days=days)
    
    # Get filter parameters
    search = request.GET.get('search', '')
    
    # Base queryset - only antivirus events
    events = SecurityEvent.objects.filter(
        event_type='antivirus',
        timestamp__gte=start_date
    )
    
    # Apply filters
    if search:
        events = events.filter(
            Q(virus_name__icontains=search) |
            Q(file_name__icontains=search) |
            Q(username__icontains=search)
        )
    
    # Statistics
    total_detections = events.count()
    unique_viruses = events.values('virus_name').distinct().count()
    
    # Top viruses
    top_viruses = events.values('virus_name').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Top affected users
    top_users = events.values('username', 'user_email').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Top infected files
    top_files = events.values('file_name').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Unique viruses for chart (top 5)
    top_malwares_pie = events.values('virus_name').annotate(
        count=Count('id')
    ).order_by('-count')[:5]
    
    # Pagination
    paginator = Paginator(events.order_by('-timestamp'), 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'events': page_obj,
        'total_detections': total_detections,
        'unique_viruses': unique_viruses,
        'top_viruses': list(events.values('virus_name').annotate(count=Count('id')).order_by('-count')[:10]),
        'top_users': list(events.values('username', 'user_email').annotate(count=Count('id')).order_by('-count')[:10]),
        'top_files': list(events.values('file_name').annotate(count=Count('id')).order_by('-count')[:10]),
        'top_malwares_pie': list(events.values('virus_name').annotate(count=Count('id')).order_by('-count')[:5]),
        'days': days,
        'search': search,
    }
    
    return render(request, 'security_events/antivirus.html', context)


@login_required
def webfilter_dashboard(request):
    """Web Filter dashboard"""
    # Get date range
    days = int(request.GET.get('days', 7))
    start_date = timezone.now() - timedelta(days=days)
    
    # Get filter parameters
    category = request.GET.get('category', '')
    action = request.GET.get('action', '')
    search = request.GET.get('search', '')
    
    # Advanced Filters
    username_q = request.GET.get('username', '')
    url_q = request.GET.get('url', '')
    department_q = request.GET.get('department', '')
    
    # Sorting
    ordering = request.GET.get('ordering', '-timestamp')
    
    # Base queryset - only webfilter events
    events = SecurityEvent.objects.filter(
        event_type='webfilter',
        timestamp__gte=start_date
    )
    
    # Apply filters
    if category:
        events = events.filter(category=category)
    if action:
        events = events.filter(action=action)
    if search:
        events = events.filter(
            Q(url__icontains=search) |
            Q(username__icontains=search) |
            Q(category__icontains=search)
        )
        
    if username_q:
        events = events.filter(
            Q(username__icontains=username_q) | 
            Q(ad_display_name__icontains=username_q)
        )
    if url_q:
        events = events.filter(url__icontains=url_q)
    if department_q:
        events = events.filter(user_department__icontains=department_q)
    
    # Apply sorting
    if ordering:
        events = events.order_by(ordering)
    
    # Statistics
    total_blocks = events.filter(action='blocked').count()
    total_events = events.count()
    
    # Top blocked categories
    top_categories = events.filter(action='blocked').order_by().values('category').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Top users with blocks
    top_users = events.filter(action='blocked').order_by().values('username', 'user_email').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Top blocked URLs
    top_urls = events.filter(action='blocked').order_by().values('url').annotate(
        count=Count('id')
    ).order_by('-count')[:10]
    
    # Get all categories for filter
    all_categories = events.order_by().values_list('category', flat=True).distinct()
    
    # Blocked actions over time
    blocks_over_time = [
        {'date': str(d['date']), 'count': d['count']}
        for d in events.filter(action='blocked').order_by().values('date').annotate(count=Count('id')).order_by('date')
    ]
    
    # Pagination
    paginator = Paginator(events, 50)
    page_number = request.GET.get('page', 1)
    page_obj = paginator.get_page(page_number)
    
    context = {
        'events': page_obj,
        'total_blocks': total_blocks,
        'total_events': total_events,
        'top_categories': list(events.filter(action='blocked').order_by().values('category').annotate(count=Count('id')).order_by('-count')[:10]),
        'top_users': list(events.filter(action='blocked').order_by().values('username', 'user_email').annotate(count=Count('id')).order_by('-count')[:10]),
        'top_urls': list(events.filter(action='blocked').order_by().values('url').annotate(count=Count('id')).order_by('-count')[:10]),
        'blocks_over_time': blocks_over_time,
        'all_categories': all_categories,
        'days': days,
        'category': category,
        'action': action,
        'search': search,
        'username_q': username_q,
        'url_q': url_q,
        'department_q': department_q,
        'ordering': ordering,
    }
    
    return render(request, 'security_events/webfilter_v2.html', context)
