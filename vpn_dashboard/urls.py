from django.contrib import admin
from django.urls import path, include
from django.views.generic import RedirectView
from django.shortcuts import redirect
from django.http import Http404
from dashboard import views
from integrations import views as integration_views

from django.conf import settings
from django.conf.urls.static import static

def catch_all_redirect(request, undefined_path=None):
    """
    Redireciona qualquer rota inválida:
    - Se o usuário estiver logado: redireciona para o dashboard principal.
    - Se o usuário NÃO estiver logado: redireciona para a página de login.
    Exceto por arquivos estáticos ou de mídia ausentes para não poluir o console com mime-types.
    """
    if undefined_path and any(undefined_path.lower().endswith(ext) for ext in [
        '.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.map', '.woff', '.woff2', '.json'
    ]):
        raise Http404("Estático não encontrado")
    
    if request.user.is_authenticated:
        return redirect('dashboard:index')
    return redirect('/admin/login/')

def custom_handler404(request, exception=None):
    """
    Handler 404 global do Django (ativado em produção com DEBUG=False).
    - Se o usuário estiver logado: redireciona para o dashboard principal.
    - Se o usuário NÃO estiver logado: redireciona para a página de login.
    """
    if request.user.is_authenticated:
        return redirect('dashboard:index')
    return redirect('/admin/login/')

handler404 = 'vpn_dashboard.urls.custom_handler404'

urlpatterns = [
    path('health/', views.health_check, name='health_check'),
    path('setup/', include('setup.urls')),
    path('admin/utils/ad-groups/', integration_views.search_ad_groups, name='search_ad_groups'),
    path('admin/', admin.site.urls),
    path('login/', RedirectView.as_view(url='/admin/login/', permanent=True)),
    path('', include('dashboard.urls')),
    path('security/', include('security_events.urls')),
    path('api/security-events/', include('security_events.api.urls')),  # API routes
    path('api/stats/', views.dashboard_stats_api, name='dashboard_stats_api'),
    path('<path:undefined_path>', catch_all_redirect, name='catch_all_redirect'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
