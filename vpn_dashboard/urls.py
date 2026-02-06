from django.contrib import admin
from django.urls import path, include
from dashboard import views
from integrations import views as integration_views

urlpatterns = [
    path('admin/utils/ad-groups/', integration_views.search_ad_groups, name='search_ad_groups'),
    path('admin/', admin.site.urls),
    path('', include('dashboard.urls')),
    path('api/stats/', views.dashboard_stats_api, name='dashboard_stats_api'),
]
