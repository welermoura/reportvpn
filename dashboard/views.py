from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.views.generic import ListView
from django.utils import timezone
from datetime import timedelta
from vpn_logs.models import VPNLog
from integrations.models import FortiAnalyzerConfig
from django.db.models import Sum, Count, Q, Subquery, OuterRef, IntegerField, Case, When, Value

# ... (imports remain the same)

class VPNLogListView(LoginRequiredMixin, ListView):
    model = VPNLog
    template_name = 'dashboard/index.html'
    context_object_name = 'logs'
    paginate_by = 20
    
    def get_queryset(self):
        queryset = super().get_queryset()
        
        # Load Trusted Countries
        config = FortiAnalyzerConfig.load()
        trusted_countries = [c.strip().upper() for c in config.trusted_countries.split(',')]
        
        # Specific Column Filters
        user_q = self.request.GET.get('user_q')
        title_q = self.request.GET.get('title_q')
        dept_q = self.request.GET.get('dept_q')
        
        if user_q:
            queryset = queryset.filter(
                Q(user__icontains=user_q) | Q(ad_display_name__icontains=user_q)
            )
        if title_q:
            queryset = queryset.filter(ad_title__icontains=title_q)
        if dept_q:
            queryset = queryset.filter(ad_department__icontains=dept_q)

        # Legacy general search (optional support)
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
                queryset = queryset.filter(start_time__date=filter_date)
            except ValueError:
                pass
        
        # Annotation for Volume Sorting
        queryset = queryset.annotate(
            total_volume=Sum('bandwidth_in') + Sum('bandwidth_out')
        )

        # Annotate with daily connection count for each user
        daily_count_subquery = VPNLog.objects.filter(
            user=OuterRef('user'),
            start_time__date=OuterRef('start_time__date')
        ).values('user').annotate(
            count=Count('id')
        ).values('count')
        
        # Add Subquery to main queryset
        qs = queryset.annotate(
            daily_connection_count=Subquery(daily_count_subquery, output_field=IntegerField())
        )

        # Annotate Suspicious Activity 
        # (Assuming country_code is stored as 2-letter ISO, match directly or handle nulls)
        qs = qs.annotate(
            is_suspicious=Case(
                When(country_code__in=trusted_countries, then=Value(0)),
                When(country_code__isnull=True, then=Value(0)), # Null country not necessarily suspicious? Or maybe 0.5? sticking to 0 for now.
                default=Value(1),
                output_field=models.IntegerField()
            )
        )

        # Dynamic Ordering
        ordering = self.request.GET.get('ordering')
        
        if ordering:
             # Map virtual fields if necessary
            if ordering == 'volume':
                ordering = '-total_volume'
            elif ordering == '-volume':
                ordering = 'total_volume'
            
            # User specific ordering overrides suspicion sorting? 
            # Ideally suspicion should always be top priority unless explicitly sorting by something else?
            # Creating a composite ordering: Suspicious first, then the requested field.
            return qs.order_by('-is_suspicious', ordering)
        
        # Default ordering: Suspicious first, then recent time
        return qs.order_by('-is_suspicious', '-start_time')

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

# ... export_logs_pdf remains similar ...

@login_required
def dashboard_stats_api(request):
    # 1. Daily Trend (Last 30 Days)
    last_30_days = timezone.now().date() - timedelta(days=30)
    daily_trend = VPNLog.objects.filter(start_time__date__gte=last_30_days)\
        .values('start_time__date')\
        .annotate(count=Count('id'))\
        .order_by('start_time__date')
        
    trend_data = {
        'labels': [entry['start_time__date'].strftime('%d/%m') for entry in daily_trend],
        'data': [entry['count'] for entry in daily_trend]
    }
    
    # 2. Top 5 Departments
    top_depts = VPNLog.objects.exclude(ad_department__isnull=True).exclude(ad_department='')\
        .values('ad_department')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]
        
    dept_data = {
        'labels': [entry['ad_department'] for entry in top_depts],
        'data': [entry['count'] for entry in top_depts]
    }

    # 3. Top 5 Titles (Cargos) - [NEW]
    top_titles = VPNLog.objects.exclude(ad_title__isnull=True).exclude(ad_title='')\
        .values('ad_title')\
        .annotate(count=Count('id'))\
        .order_by('-count')[:5]

    title_data = {
        'labels': [entry['ad_title'] for entry in top_titles],
        'data': [entry['count'] for entry in top_titles]
    }
    
    # 4. Top 5 Users by Volume
    top_users = VPNLog.objects.values('user')\
        .annotate(total_bytes=Sum('bandwidth_in') + Sum('bandwidth_out'))\
        .order_by('-total_bytes')[:5]
        
    user_data = {
        'labels': [entry['user'] for entry in top_users],
        'data': [round(entry['total_bytes'] / (1024*1024), 2) for entry in top_users] # MB
    }
    
    return JsonResponse({
        'trend': trend_data,
        'departments': dept_data,
        'titles': title_data,
        'users': user_data
    })
