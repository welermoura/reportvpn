from django.contrib import admin
from django.urls import path, include
from dashboard import views
from integrations import views as integration_views

from django.conf import settings
from django.conf.urls.static import static

urlpatterns = [
    path('setup/', include('setup.urls')),
    path('admin/utils/ad-groups/', integration_views.search_ad_groups, name='search_ad_groups'),
    path('admin/', admin.site.urls),
    path('', include('dashboard.urls')),
    path('security/', include('security_events.urls')),
    path('api/security-events/', include('security_events.api.urls')),  # API routes
    path('api/stats/', views.dashboard_stats_api, name='dashboard_stats_api'),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
