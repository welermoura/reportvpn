from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.generic import ListView
from django.utils import timezone
from datetime import timedelta
from vpn_logs.models import VPNLog
from integrations.models import FortiAnalyzerConfig
from .utils import export_to_xlsx
from django.db.models import Sum, Count, Max, Q, Subquery, OuterRef, IntegerField, Case, When, Value
from django.shortcuts import render
from django.http import HttpResponse, JsonResponse
from django.template.loader import get_template
from io import BytesIO
import datetime

@login_required
def portal(request):
    """Main portal selection page"""
    from .models import PortalModule
    modules = PortalModule.objects.filter(is_active=True).order_by('order')
    return render(request, 'dashboard/portal.html', {'modules': modules})

class VPNLogListView(LoginRequiredMixin, ListView):
    model = VPNLog
    template_name = 'dashboard/index.html'
    context_object_name = 'logs'
    paginate_by = 20

    def get_template_names(self):
        if self.request.headers.get('HX-Request') == 'true':
            return ['dashboard/partials/logs_table.html']
        return ['dashboard/vpn_react.html']
    
    def get_queryset(self):
        # Start with base queryset
        # Start with base queryset (SSL Only)
        queryset = VPNLog.objects.filter(
            Q(raw_data__tunneltype__icontains='ssl') | 
            Q(raw_data__vpntunnel__icontains='ssl')
        )
        
        # Load Trusted Countries (keeping logic if needed for future, but row coloring might need adjustment)
        config = FortiAnalyzerConfig.load()
        trusted_countries = [c.strip().upper() for c in config.trusted_countries.split(',')]
        
        # Filter Logic (Keep existing filters)
        # 1. User Filter
        user_q = self.request.GET.get('user_q')
        if user_q:
            queryset = queryset.filter(
                Q(user__icontains=user_q) | Q(ad_display_name__icontains=user_q)
            )

        # 2. Title Filter
        title_q = self.request.GET.get('title_q')
        if title_q:
            queryset = queryset.filter(ad_title__icontains=title_q)

        # 3. Dept Filter
        dept_q = self.request.GET.get('dept_q')
        if dept_q:
            queryset = queryset.filter(ad_department__icontains=dept_q)

        # 4. General Search
        query = self.request.GET.get('q')
        if query:
            queryset = queryset.filter(
                Q(user__icontains=query) | 
                Q(ad_department__icontains=query) |
                Q(ad_display_name__icontains=query)
            )
            
        # 5. Date Filter
        date_str = self.request.GET.get('date')
        if date_str:
            try:
                filter_date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
                queryset = queryset.filter(start_date=filter_date)
            except ValueError:
                pass
        
        # --- Aggregation Logic (Group by User) ---
        
        # Subquery for latest connection details (for context like IP, City)
        # We order by -start_time to get the latest.
        # Note: This subquery is correlated to the outer query via user=OuterRef('user')
        latest_log_qs = VPNLog.objects.filter(user=OuterRef('user')).order_by('-start_time')
        
        # Aggregation Logic
        # 1. Clear any existing ordering which might break grouping
        # 2. Group by user fields
        # 3. Annotate metrics
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
            # Fetch details from the latest log
            latest_source_ip=Subquery(latest_log_qs.values('source_ip')[:1]),
            latest_city=Subquery(latest_log_qs.values('city')[:1]),
            latest_country=Subquery(latest_log_qs.values('country_name')[:1]),
            latest_country_code=Subquery(latest_log_qs.values('country_code')[:1])
        )

        # Dynamic Ordering
        ordering = self.request.GET.get('ordering')
        
        if ordering:
            if ordering == 'volume':
                qs = qs.order_by('-total_volume')
            elif ordering == '-volume':
                qs = qs.order_by('total_volume')
            elif ordering == 'duration':
                 qs = qs.order_by('-total_duration')
            elif ordering == '-duration':
                 qs = qs.order_by('total_duration')
            elif ordering == 'start_time': 
                 qs = qs.order_by('-last_connection')
            elif ordering == '-start_time':
                 qs = qs.order_by('last_connection')
            elif ordering == 'user':
                 qs = qs.order_by('user')
            elif ordering == '-user':
                 qs = qs.order_by('-user')
            # Add other fields as needed
            
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        queryset = self.get_queryset() # This re-evaluates, but necessary for stats based on filtered view if desired, though stats usually global.
        # Actually stats in context are global usually.
        # Let's keep existing logic but careful about queryset re-use if expensive.
        
        # Estatísticas (Global context relative to current filters if we reused logic properly, 
        # but the original code did a rough count. Let's keep it simple.)
        # Note: 'queryset' here allows filtering stats by the current search, which is good.
        
        context['active_users_count'] = queryset.values('user').distinct().count()
        
        total_in = queryset.aggregate(Sum('bandwidth_in'))['bandwidth_in__sum'] or 0
        total_out = queryset.aggregate(Sum('bandwidth_out'))['bandwidth_out__sum'] or 0
        total_bytes = total_in + total_out
        
        # Formatar volume total
        gb = total_bytes / (1024 * 1024 * 1024)
        if gb >= 1:
            context['total_volume'] = f"{gb:.2f} GB"
        else:
            mb = total_bytes / (1024 * 1024)
            context['total_volume'] = f"{mb:.2f} MB"
            
        # Trusted Countries
        config = FortiAnalyzerConfig.load()
        context['trusted_countries'] = [c.strip() for c in config.trusted_countries.split(',')]
            
        return context

class BruteForceListView(LoginRequiredMixin, ListView):
    from vpn_logs.models import VPNFailure
    model = VPNFailure
    template_name = 'dashboard/bruteforce_react.html'
    context_object_name = 'failures'

    def get_template_names(self):
        if self.request.headers.get('HX-Request') == 'true':
            return ['dashboard/partials/bruteforce_table.html'] # Create if needed or just return react
        return ['dashboard/bruteforce_react.html']
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        from vpn_logs.models import VPNFailure
        context['total_failures'] = VPNFailure.objects.count()
        return context

@login_required
def export_logs_pdf(request):
    # Reuse filtering logic manually since we are not in a ListView
    # Reuse filtering logic manually since we are not in a ListView
    # SSL Only
    queryset = VPNLog.objects.filter(
        Q(raw_data__tunneltype__icontains='ssl') | 
        Q(raw_data__vpntunnel__icontains='ssl')
    )
    
    # 1. Date Filter
    date_str = request.GET.get('date')
    if date_str:
        queryset = queryset.filter(start_date=date_str)
    
    # 2. Column Filters
    user_q = request.GET.get('user_q')
    if user_q:
        queryset = queryset.filter(user__icontains=user_q)

    title_q = request.GET.get('title_q')
    if title_q:
        queryset = queryset.filter(ad_title__icontains=title_q)

    dept_q = request.GET.get('dept_q')
    if dept_q:
        queryset = queryset.filter(ad_department__icontains=dept_q)

    # 3. Annotation (Copying logic from ListView)
    daily_count_subquery = VPNLog.objects.filter(
        user=OuterRef('user'), 
        start_date=OuterRef('start_date')
    ).order_by().values('user').annotate(count=Count('id')).values('count')
    
    logs = queryset.annotate(
        daily_connection_count=Subquery(daily_count_subquery, output_field=IntegerField())
    ).order_by('-start_time')

    # Prepare context
    filter_desc = []
    if date_str: filter_desc.append(f"Data: {date_str}")
    if user_q: filter_desc.append(f"User: {user_q}")
    if title_q: filter_desc.append(f"Cargo: {title_q}")
    if dept_q: filter_desc.append(f"Depto: {dept_q}")
    
    context = {
        'logs': logs,
        'filter_desc': " | ".join(filter_desc) if filter_desc else "Todos os registros"
    }

    # Render PDF
    template = get_template('dashboard/pdf_template.html')
    html = template.render(context)
    result = BytesIO()
    
    try:
        from xhtml2pdf import pisa
        pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result)
        if not pdf.err:
            response = HttpResponse(result.getvalue(), content_type='application/pdf')
            filename = f"vpn_report_{timezone.now().strftime('%Y%m%d_%H%M')}.pdf"
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
    except ImportError:
        return HttpResponse("Library 'xhtml2pdf' not installed.", status=500)
    except Exception as e:
        return HttpResponse(f"Erro ao gerar PDF: {str(e)}", status=500)
    
    return HttpResponse("Erro ao gerar PDF", status=500)

@login_required
def export_logs_xlsx(request):
    # SSL Only
    queryset = VPNLog.objects.filter(
        Q(raw_data__tunneltype__icontains='ssl') | 
        Q(raw_data__vpntunnel__icontains='ssl')
    )
    
    # Apply Filters (Same as PDF)
    date_str = request.GET.get('date')
    if date_str:
        queryset = queryset.filter(start_date=date_str)
        
    user_q = request.GET.get('user_q')
    if user_q:
        queryset = queryset.filter(user__icontains=user_q)

    title_q = request.GET.get('title_q')
    if title_q:
        queryset = queryset.filter(ad_title__icontains=title_q)

    dept_q = request.GET.get('dept_q')
    if dept_q:
        queryset = queryset.filter(ad_department__icontains=dept_q)
        
    queryset = queryset.order_by('-start_time')
    
    headers = ['Data/Hora', 'Usuário', 'Origem', 'Conectado em', 'Duração', 'Volume']
    
    def format_volume(obj):
        bytes_val = (obj.bandwidth_in or 0) + (obj.bandwidth_out or 0)
        gb = bytes_val / (1024 ** 3)
        if gb >= 1: return f"{gb:.2f} GB"
        return f"{(bytes_val / (1024 ** 2)):.2f} MB"

    field_mapping = [
        lambda x: x.start_time.strftime('%d/%m/%Y %H:%M') if x.start_time else '',
        'user',
        'source_ip',
        'city',
        'duration', # You might want to format duration too if it's seconds
        format_volume
    ]
    
    filename = f"vpn_report_{timezone.now().strftime('%Y%m%d_%H%M')}.xlsx"
    return export_to_xlsx(queryset, filename, headers, field_mapping)

@login_required
def dashboard_stats_api(request):
    # Base QuerySet for Stats (SSL Only)
    base_qs = VPNLog.objects.filter(
        Q(raw_data__tunneltype__icontains='ssl') | 
        Q(raw_data__vpntunnel__icontains='ssl')
    )

    # 1. Daily Trend (Last 30 Days)
    last_30_days = timezone.now().date() - timedelta(days=30)
    daily_trend = base_qs.filter(start_date__gte=last_30_days)\
        .order_by()\
        .values('start_date')\
        .annotate(count=Count('id'))\
        .order_by('start_date')
        
    trend_data = {
        'labels': [entry['start_date'].strftime('%d/%m') for entry in daily_trend],
        'keys': [entry['start_date'].strftime('%Y-%m-%d') for entry in daily_trend],
        'data': [entry['count'] for entry in daily_trend]
    }
    
    # 2. Top 5 Departments
    top_depts = base_qs.exclude(ad_department__isnull=True).exclude(ad_department='')\
        .order_by()\
        .values('ad_department')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]
        
    dept_data = {
        'labels': [entry['ad_department'] for entry in top_depts],
        'data': [entry['count'] for entry in top_depts]
    }

    # 3. Top 5 Titles (Cargos) - [NEW]
    top_titles = base_qs.exclude(ad_title__isnull=True).exclude(ad_title='')\
        .order_by()\
        .values('ad_title')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]

    title_data = {
        'labels': [entry['ad_title'] for entry in top_titles],
        'data': [entry['count'] for entry in top_titles]
    }
    
    # 4. Top 5 Users by Volume
    top_users = base_qs.order_by()\
        .values('user')\
        .annotate(total_bytes=Sum('bandwidth_in') + Sum('bandwidth_out'))\
        .order_by('-total_bytes')[:5]
        
    user_data = {
        'labels': [entry['user'] for entry in top_users],
        'data': [round(entry['total_bytes'] / (1024*1024), 2) for entry in top_users] # MB
    }
    
    # 5. Period Totals (Based on filtered date or today)
    date_str = request.GET.get('date')
    if date_str:
        try:
            target_date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
        except ValueError:
            target_date = timezone.localtime(timezone.now()).date()
    else:
        target_date = timezone.localtime(timezone.now()).date()

    period_logs = base_qs.filter(start_time__date=target_date)
    
    period_stats = {
        'total_connections': period_logs.count(), 
        'active_users': period_logs.values('user').distinct().count(),
        'total_volume_bytes': period_logs.aggregate(vol=Sum('bandwidth_in') + Sum('bandwidth_out'))['vol'] or 0
    }

    # 6. Top Brute Force Targets (Failures) [NEW]
    from vpn_logs.models import VPNFailure
    top_failures = VPNFailure.objects.values('user')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]

    failure_data = {
        'labels': [entry['user'] for entry in top_failures],
        'data': [entry['count'] for entry in top_failures]
    }
    
    return JsonResponse({
        'trend': trend_data,
        'departments': dept_data,
        'titles': title_data,
        'users': user_data,
        'failures': failure_data,
        'period_stats': period_stats
    })

@login_required
def bruteforce_stats_api(request):
    from vpn_logs.models import VPNFailure
    from django.db.models.functions import TruncHour, TruncDay
    
    # 1. Failures Over Time (Last 24 Hours)
    last_24h = timezone.now() - timedelta(hours=24)
    trend = VPNFailure.objects.filter(timestamp__gte=last_24h)\
        .annotate(hour=TruncHour('timestamp'))\
        .values('hour')\
        .annotate(count=Count('id'))\
        .order_by('hour')
        
    trend_data = {
        'labels': [entry['hour'].strftime('%H:00') for entry in trend],
        'data': [entry['count'] for entry in trend]
    }

    # 2. Top Attackers (Source IP)
    top_ips = VPNFailure.objects.values('source_ip', 'country_code')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]
        
    ip_data = {
        'labels': [f"{entry['source_ip']} ({entry['country_code'] or '?'})" for entry in top_ips],
        'data': [entry['count'] for entry in top_ips]
    }

    # 3. Top Targets (Users)
    top_users = VPNFailure.objects.values('user')\
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
