"""Security Events Views"""
from django.shortcuts import render
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models import Q, Count
from django.utils import timezone
from datetime import timedelta
from .models import SecurityEvent
import csv
from django.http import HttpResponse
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


@login_required
def webfilter_react_dashboard(request):
    """React-based webfilter dashboard - data loaded via API"""
    return render(request, 'security_events/webfilter_react.html')


@login_required
def export_events_pdf(request):
    """Export security events to PDF"""
    # 1. Filter Logic (Reused from index)
    days = int(request.GET.get('days', 7))
    start_date = timezone.now() - timedelta(days=days)
    
    event_type = request.GET.get('event_type', '')
    severity = request.GET.get('severity', '')
    search = request.GET.get('search', '')
    
    events = SecurityEvent.objects.filter(timestamp__gte=start_date).order_by('-timestamp')
    
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

    # 2. Context Preparation
    filter_desc = []
    filter_desc.append(f"Últimos {days} dias")
    if event_type: filter_desc.append(f"Tipo: {event_type}")
    if severity: filter_desc.append(f"Severidade: {severity}")
    if search: filter_desc.append(f"Busca: {search}")
    
    context = {
        'events': events[:1000], # Limit to 1000 for PDF performance
        'filter_desc': " | ".join(filter_desc)
    }

    # 3. Render PDF
    template = get_template('security_events/pdf_report.html')
    html = template.render(context)
    result = BytesIO()
    
    try:
        from xhtml2pdf import pisa
        pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result)
        if not pdf.err:
            response = HttpResponse(result.getvalue(), content_type='application/pdf')
            filename = f"security_report_{timezone.now().strftime('%Y%m%d_%H%M')}.pdf"
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
    except ImportError:
        return HttpResponse("Library 'xhtml2pdf' not installed.", status=500)
    except Exception as e:
        return HttpResponse(f"Erro ao gerar PDF: {str(e)}", status=500)

    return HttpResponse("Erro ao gerar PDF", status=500)


@login_required
def export_events_csv(request):
    """Export security events to CSV"""
    # 1. Filter Logic
    days = int(request.GET.get('days', 7))
    start_date = timezone.now() - timedelta(days=days)
    
    event_type = request.GET.get('event_type', '')
    severity = request.GET.get('severity', '')
    search = request.GET.get('search', '')
    
    events = SecurityEvent.objects.filter(timestamp__gte=start_date).order_by('-timestamp')
    
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
        
    response = HttpResponse(content_type='text/csv')
    filename = f"security_events_{timezone.now().strftime('%Y%m%d_%H%M')}.csv"
    response['Content-Disposition'] = f'attachment; filename="{filename}"'
    
    writer = csv.writer(response)
    writer.writerow(['Data/Hora', 'Tipo', 'Severidade', 'Origem', 'País Origem', 'Destino', 'País Destino', 'Usuário', 'Detalhes'])
    
    # Export up to 5000 records for CSV
    for event in events[:5000]:
        details = ""
        if event.event_type == 'ips':
            details = f"Attack: {event.attack_name} (CVE: {event.cve})"
        elif event.event_type == 'antivirus':
            details = f"Virus: {event.virus_name} (File: {event.file_name})"
        elif event.event_type == 'webfilter':
            details = f"URL: {event.url} (Cat: {event.category})"
            
        writer.writerow([
            event.timestamp.strftime("%d/%m/%Y %H:%M:%S"),
            event.get_event_type_display(),
            event.severity,
            event.src_ip,
            event.src_country,
            event.dst_ip,
            event.dst_country,
            event.username,
            details
        ])
        
    return response

@login_required
def export_webfilter_xlsx(request):
    """Export Webfilter events to XLSX"""
    # Base queryset
    events = SecurityEvent.objects.filter(event_type='webfilter')
    
    # Filters matching API/React Dashboard
    username_q = request.GET.get('username')
    if username_q:
        events = events.filter(Q(username__icontains=username_q) | Q(ad_display_name__icontains=username_q))
        
    url_q = request.GET.get('url')
    if url_q:
        events = events.filter(url__icontains=url_q)
        
    dept_q = request.GET.get('department')
    if dept_q:
        events = events.filter(user_department__icontains=dept_q)
        
    category = request.GET.get('category')
    if category:
        events = events.filter(category=category)
        
    action = request.GET.get('action')
    if action:
        events = events.filter(action=action)
        
    # Date Filtering (Handle both 'days' and 'start_date'/'end_date')
    start_date_str = request.GET.get('start_date')
    end_date_str = request.GET.get('end_date')
    
    if start_date_str:
        events = events.filter(timestamp__gte=start_date_str)
    elif request.GET.get('days'): # Fallback to days if no specific start date
        days = int(request.GET.get('days', 7))
        events = events.filter(timestamp__gte=timezone.now() - timedelta(days=days))
        
    if end_date_str:
        events = events.filter(timestamp__lte=f"{end_date_str} 23:59:59")
        
    events = events.order_by('-timestamp')[:5000] # Limit 5k
    
    headers = ['Data/Hora', 'Usuário', 'Depto', 'IP Origem', 'Categoria', 'URL', 'Ação']
    field_mapping = [
        lambda x: x.timestamp.strftime('%d/%m/%Y %H:%M:%S'),
        lambda x: x.ad_display_name or x.username,
        'user_department',
        'src_ip',
        'category',
        'url',
        'action'
    ]
    
    filename = f"webfilter_report_{timezone.now().strftime('%Y%m%d_%H%M')}.xlsx"
    return export_to_xlsx(events, filename, headers, field_mapping)

@login_required
def export_webfilter_pdf(request):
    """Export Webfilter events to PDF"""
    # Reuse filter logic (Copy-paste for now to keep independent)
    events = SecurityEvent.objects.filter(event_type='webfilter')
    
    username_q = request.GET.get('username')
    if username_q:
        events = events.filter(Q(username__icontains=username_q) | Q(ad_display_name__icontains=username_q))
        
    url_q = request.GET.get('url')
    if url_q:
        events = events.filter(url__icontains=url_q)
        
    dept_q = request.GET.get('department')
    if dept_q:
        events = events.filter(user_department__icontains=dept_q)
        
    category = request.GET.get('category')
    if category:
        events = events.filter(category=category)
        
    action = request.GET.get('action')
    if action:
        events = events.filter(action=action)
        
    start_date_str = request.GET.get('start_date')
    if start_date_str:
        events = events.filter(timestamp__gte=start_date_str)
    elif request.GET.get('days'):
        days = int(request.GET.get('days', 7))
        events = events.filter(timestamp__gte=timezone.now() - timedelta(days=days))
        
    end_date_str = request.GET.get('end_date')
    if end_date_str:
        events = events.filter(timestamp__lte=f"{end_date_str} 23:59:59")
        
    events = events.order_by('-timestamp')[:1000] # Limit 1k for PDF
    
    # Context
    filter_desc = []
    if category: filter_desc.append(f"Cat: {category}")
    if action: filter_desc.append(f"Ação: {action}")
    if username_q: filter_desc.append(f"User: {username_q}")
    
    context = {
        'events': events,
        'filter_desc': " | ".join(filter_desc) or "Todos os eventos",
        'title': 'Relatório de Filtro Web'
    }
    
    template = get_template('security_events/pdf_report.html')
    html = template.render(context)
    result = BytesIO()
    
    try:
        from xhtml2pdf import pisa
        pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result)
        if not pdf.err:
            response = HttpResponse(result.getvalue(), content_type='application/pdf')
            filename = f"webfilter_report_{timezone.now().strftime('%Y%m%d_%H%M')}.pdf"
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
    except ImportError:
        return HttpResponse("Library 'xhtml2pdf' not installed.", status=500)
    except Exception as e:
        return HttpResponse(f"Erro ao gerar PDF: {str(e)}", status=500)
    
    return HttpResponse("Erro ao gerar PDF", status=500)
