from io import BytesIO
from django.http import HttpResponse
from django.contrib.auth.mixins import LoginRequiredMixin
from django.contrib.auth.decorators import login_required
from django.views.generic import ListView
from django.utils import timezone
from django.template.loader import get_template

from vpn_logs.models import VPNFailure

class BruteForceListView(LoginRequiredMixin, ListView):
    model = VPNFailure
    template_name = 'dashboard/bruteforce_react.html'
    context_object_name = 'failures'

    def get_template_names(self):
        if self.request.headers.get('HX-Request') == 'true':
            return ['dashboard/partials/bruteforce_table.html']
        return ['dashboard/bruteforce_react.html']
    
    def get_context_data(self, **kwargs):
        context = super().get_context_data(**kwargs)
        context['total_failures'] = VPNFailure.objects.count()
        return context

@login_required
def export_bruteforce_pdf(request):
    queryset = VPNFailure.objects.all()
    
    date_str = request.GET.get('date')
    if date_str:
        queryset = queryset.filter(timestamp__date=date_str)
    
    user_q = request.GET.get('user')
    if user_q:
        queryset = queryset.filter(user__icontains=user_q)

    ip_q = request.GET.get('ip')
    if ip_q:
        queryset = queryset.filter(source_ip__icontains=ip_q)
    
    failures = queryset.order_by('-timestamp')[:1000] # Reasonal limit for PDF

    filter_desc = []
    if date_str: filter_desc.append(f"Data: {date_str}")
    if user_q: filter_desc.append(f"Usuário: {user_q}")
    if ip_q: filter_desc.append(f"IP: {ip_q}")
    
    context = {
        'failures': failures,
        'filter_desc': " | ".join(filter_desc) if filter_desc else "Todos os registros"
    }

    template = get_template('dashboard/bruteforce_pdf_template.html')
    html = template.render(context)
    result = BytesIO()
    
    try:
        from xhtml2pdf import pisa
        pdf = pisa.pisaDocument(BytesIO(html.encode("UTF-8")), result)
        if not pdf.err:
            response = HttpResponse(result.getvalue(), content_type='application/pdf')
            filename = f"bruteforce_report_{timezone.now().strftime('%Y%m%d_%H%M')}.pdf"
            response['Content-Disposition'] = f'attachment; filename="{filename}"'
            return response
    except Exception as e:
        return HttpResponse(f"Erro ao gerar PDF: {str(e)}", status=500)
    
    return HttpResponse("Erro ao gerar PDF", status=500)
