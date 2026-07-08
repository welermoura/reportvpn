import datetime
from io import BytesIO
from django.http import HttpResponse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.views.generic import ListView
from django.db.models import Sum, Count, Max, Q, Subquery, OuterRef, IntegerField
from django.utils import timezone
from django.template.loader import get_template

from vpn_logs.models import VPNLog
from integrations.models import FortiAnalyzerConfig
from ..utils import export_to_xlsx

class VPNLogListView(LoginRequiredMixin, ListView):
    model = VPNLog
    template_name = 'dashboard/dashboard_premium.html'
    context_object_name = 'logs'
    paginate_by = 20

    def get_template_names(self):
        if self.request.headers.get('HX-Request') == 'true':
            return ['dashboard/partials/logs_table.html']
        return ['dashboard/dashboard_premium.html']
    
    def get_queryset(self):
        # Detect days that already have finalized fidelity reports
        days_with_fidelity = VPNLog.objects.filter(
            session_id__startswith='fidelity_'
        ).values_list('start_date', flat=True).distinct()

        # Base queryset (Strict SSL Only)
        # Exclude regular logs for days that have fidelity logs to avoid doubling stats
        queryset = VPNLog.objects.filter(
            Q(raw_data__tunneltype__startswith='ssl') | 
            Q(raw_data__vpntype__icontains='ssl')
        ).exclude(
            ~Q(session_id__startswith='fidelity_'),
            start_date__in=days_with_fidelity
        )
        
        # Filter Logic (Keep existing filters)
        user_q = self.request.GET.get('user_q')
        if user_q:
            queryset = queryset.filter(
                Q(user__icontains=user_q) | Q(ad_display_name__icontains=user_q)
            )

        title_q = self.request.GET.get('title_q')
        if title_q:
            queryset = queryset.filter(ad_title__icontains=title_q)

        dept_q = self.request.GET.get('dept_q')
        if dept_q:
            queryset = queryset.filter(ad_department__icontains=dept_q)

        query = self.request.GET.get('q')
        if query:
            queryset = queryset.filter(
                Q(user__icontains=query) | 
                Q(ad_department__icontains=query) |
                Q(ad_display_name__icontains=query)
            )
            
        date_str = self.request.GET.get('date')
        if date_str:
            try:
                filter_date = datetime.datetime.strptime(date_str, '%Y-%m-%d').date()
                queryset = queryset.filter(start_date=filter_date)
            except ValueError:
                pass
        
        # --- Aggregation Logic (Group by User) ---
        latest_log_qs = VPNLog.objects.filter(
            Q(user=OuterRef('user')),
            Q(raw_data__tunneltype__startswith='ssl') | 
            Q(raw_data__vpntype='ssl-vpn')
        ).order_by('-start_time')
        
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
        else:
            qs = qs.order_by('-last_connection', 'user')
            
        return qs

    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        queryset = self.get_queryset()
        
        context['active_users_count'] = queryset.values('user').distinct().count()
        
        total_in = queryset.aggregate(Sum('bandwidth_in'))['bandwidth_in__sum'] or 0
        total_out = queryset.aggregate(Sum('bandwidth_out'))['bandwidth_out__sum'] or 0
        total_bytes = total_in + total_out
        
        gb = total_bytes / (1024 * 1024 * 1024)
        if gb >= 1:
            context['total_volume'] = f"{gb:.2f} GB"
        else:
            mb = total_bytes / (1024 * 1024)
            context['total_volume'] = f"{mb:.2f} MB"
            
        config = FortiAnalyzerConfig.load()
        context['trusted_countries'] = [c.strip() for c in config.trusted_countries.split(',')]
            
        return context

@login_required
def export_logs_pdf(request):
    queryset = VPNLog.objects.filter(
        Q(raw_data__tunneltype__startswith='ssl') | 
        Q(raw_data__vpntype__icontains='ssl')
    )
    
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

    daily_count_subquery = VPNLog.objects.filter(
        user=OuterRef('user'), 
        start_date=OuterRef('start_date')
    ).order_by().values('user').annotate(count=Count('id')).values('count')
    
    logs = queryset.annotate(
        daily_connection_count=Subquery(daily_count_subquery, output_field=IntegerField())
    ).order_by('-start_time')

    filter_desc = []
    if date_str: filter_desc.append(f"Data: {date_str}")
    if user_q: filter_desc.append(f"User: {user_q}")
    if title_q: filter_desc.append(f"Cargo: {title_q}")
    if dept_q: filter_desc.append(f"Depto: {dept_q}")
    
    context = {
        'logs': logs,
        'filter_desc': " | ".join(filter_desc) if filter_desc else "Todos os registros"
    }

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
    queryset = VPNLog.objects.filter(
        Q(raw_data__tunneltype__startswith='ssl') | 
        Q(raw_data__vpntype__icontains='ssl')
    )
    
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
        'duration',
        format_volume
    ]
    
    filename = f"vpn_report_{timezone.now().strftime('%Y%m%d_%H%M')}.xlsx"
    return export_to_xlsx(queryset, filename, headers, field_mapping)
