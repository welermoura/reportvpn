import datetime
from datetime import timedelta
from django.http import JsonResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views.generic import ListView
from django.db.models import Sum, Count, Q, F
from django.utils import timezone

from vpn_logs.models import VPNLog, VPNFailure
from ..models import UserRiskScore

class UserRiskScoreListView(LoginRequiredMixin, ListView):
    model = UserRiskScore
    template_name = 'dashboard/risk_react.html'
    context_object_name = 'scores'

@login_required
def dashboard_stats_api(request):
    base_qs = VPNLog.objects.all()

    user_q = request.GET.get('user_q')
    if user_q:
        base_qs = base_qs.filter(
            Q(user__icontains=user_q) | Q(ad_display_name__icontains=user_q)
        )

    title_q = request.GET.get('title_q')
    if title_q:
        base_qs = base_qs.filter(ad_title__icontains=title_q)

    dept_q = request.GET.get('dept_q')
    if dept_q:
        base_qs = base_qs.filter(ad_department__icontains=dept_q)

    query = request.GET.get('q')
    if query:
        base_qs = base_qs.filter(
            Q(user__icontains=query) | 
            Q(ad_department__icontains=query) |
            Q(ad_display_name__icontains=query)
        )

    # 1. Daily Trend (Last 30 Days)
    last_30_days = timezone.now().date() - timedelta(days=30)
    daily_trend = base_qs.filter(start_date__gte=last_30_days)\
        .order_by()\
        .values('start_date')\
        .annotate(count=Count('id'))\
        .order_by('start_date')
        
    trend_data = [
        {
            'date': entry['start_date'].strftime('%Y-%m-%d'),
            'count': entry['count']
        } for entry in daily_trend
    ]
    
    # --- Prepare Filtered QS for other charts ---
    date_str = request.GET.get('date')
    if date_str:
        try:
            target_date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
            chart_qs = base_qs.filter(start_date=target_date)
        except ValueError:
            target_date = timezone.localtime(timezone.now()).date()
            chart_qs = base_qs.filter(start_date=target_date)
    else:
        target_date = timezone.localtime(timezone.now()).date()
        chart_qs = base_qs.filter(start_date=target_date)

    # 2. Top 5 Departments
    top_depts = chart_qs.exclude(ad_department__isnull=True).exclude(ad_department='')\
        .order_by()\
        .values('ad_department')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]
        
    dept_data = {
        'labels': [entry['ad_department'] for entry in top_depts],
        'data': [entry['count'] for entry in top_depts]
    }

    # 3. Top 5 Titles (Cargos)
    top_titles = chart_qs.exclude(ad_title__isnull=True).exclude(ad_title='')\
        .order_by()\
        .values('ad_title')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]

    title_data = {
        'labels': [entry['ad_title'] for entry in top_titles],
        'data': [entry['count'] for entry in top_titles]
    }
    
    # 4. Top 5 Users by Volume
    top_users = chart_qs.order_by()\
        .values('user')\
        .annotate(total_bytes=Sum('bandwidth_in') + Sum('bandwidth_out'))\
        .order_by('-total_bytes')[:5]
        
    user_data = {
        'labels': [entry['user'] for entry in top_users],
        'data': [round(entry['total_bytes'] / (1024*1024), 2) for entry in top_users] # MB
    }
    
    # 5. Period Totals
    period_stats = {
        'total_connections': chart_qs.count(), 
        'active_users': chart_qs.values('user').distinct().count(),
        'total_volume_bytes': chart_qs.aggregate(vol=Sum('bandwidth_in') + Sum('bandwidth_out'))['vol'] or 0
    }

    # 6. Top Brute Force Targets (Failures)
    failure_qs = VPNFailure.objects.all()
    if user_q:
        failure_qs = failure_qs.filter(user__icontains=user_q)
    if date_str:
        failure_qs = failure_qs.filter(timestamp__date=target_date)
    
    top_failures = failure_qs.values('user')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]

    failure_data = {
        'labels': [entry['user'] for entry in top_failures],
        'data': [entry['count'] for entry in top_failures]
    }
    
    return JsonResponse({
        'connections_trend': trend_data,
        'departments': dept_data,
        'titles': title_data,
        'users': user_data,
        'failures': failure_data,
        'period_stats': period_stats
    })

@login_required
def bruteforce_stats_api(request):
    from django.db.models.functions import TruncHour
    
    queryset = VPNFailure.objects.all()

    user = request.GET.get('user')
    if user:
        queryset = queryset.filter(user__icontains=user)
    
    ip = request.GET.get('ip')
    if ip:
        queryset = queryset.filter(source_ip__icontains=ip)

    start_date = request.GET.get('start_date')
    if start_date:
        try:
            target_date = datetime.datetime.strptime(start_date, '%Y-%m-%d').date()
            time_filter = Q(timestamp__date=target_date)
        except ValueError:
            time_filter = Q(timestamp__gte=timezone.now() - timedelta(hours=24))
    else:
        time_filter = Q(timestamp__gte=timezone.now() - timedelta(hours=24))

    # 1. Failures Over Time
    trend = queryset.filter(time_filter)\
        .annotate(hour=TruncHour('timestamp'))\
        .values('hour')\
        .annotate(count=Count('id'))\
        .order_by('hour')
        
    trend_data = {
        'labels': [entry['hour'].strftime('%H:00') for entry in trend],
        'data': [entry['count'] for entry in trend]
    }

    # 2. Top Attackers (Source IP)
    if not start_date:
        ip_filter = Q(timestamp__gte=timezone.now() - timedelta(hours=48))
    else:
        ip_filter = time_filter

    top_ips = queryset.filter(ip_filter).values('source_ip', 'country_code')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]
        
    ip_data = {
        'labels': [f"{entry['source_ip']} ({entry['country_code'] or '?'})" for entry in top_ips],
        'data': [entry['count'] for entry in top_ips]
    }

    # 3. Top Targets (Users)
    top_users = queryset.filter(ip_filter).values('user')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]
        
    user_data = {
        'labels': [entry['user'] for entry in top_users],
        'data': [entry['count'] for entry in top_users]
    }
    
    return JsonResponse({
        'trend': trend_data,
        'ips': ip_data,
        'users': user_data
    })

@login_required
def risk_stats_api(request):
    """API for User Risk Scoring Dashboard statistics — otimizada com suporte a data"""
    start_date = request.GET.get('start_date')
    end_date = request.GET.get('end_date')
    user = request.GET.get('user')
    level = request.GET.get('level')

    queryset = UserRiskScore.objects.all()
    
    if user:
        queryset = queryset.filter(username__icontains=user)
    if level:
        queryset = queryset.filter(risk_level__iexact=level)

    if start_date or end_date:
        event_filter = Q()
        if start_date:
            event_filter &= Q(events__timestamp__date__gte=start_date)
        if end_date:
            event_filter &= Q(events__timestamp__date__lte=end_date)
        
        queryset = queryset.annotate(
            display_score=Sum('events__weight_added', filter=event_filter)
        ).filter(display_score__gt=0)
    else:
        queryset = queryset.filter(current_score__gt=0).annotate(
            display_score=F('current_score')
        )

    dist_rows = queryset.values('risk_level').annotate(count=Count('id')).order_by('-count')
    dist_data = {
        'labels': [r['risk_level'] for r in dist_rows],
        'data': [r['count'] for r in dist_rows]
    }
    
    top_risk = queryset.order_by('-display_score')[:10]
    top_data = {
        'labels': [entry.username for entry in top_risk],
        'data': [entry.display_score for entry in top_risk]
    }
    
    return JsonResponse({
        'distribution': dist_data,
        'top_risk': top_data
    })
