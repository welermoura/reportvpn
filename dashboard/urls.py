from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views import VPNLogListView
from .api.views import VPNLogViewSet, VPNFailureViewSet
from .api.timeline_view import UserTimelineViewSet

router = DefaultRouter()
router.register(r'vpn-logs', VPNLogViewSet, basename='vpn-logs-api')
router.register(r'vpn-failures', VPNFailureViewSet, basename='vpn-failures-api')
router.register(r'user-timeline', UserTimelineViewSet, basename='user-timeline')

app_name = 'dashboard'

urlpatterns = [
    path('', views.portal, name='index'),
    path('vpn-reports/', VPNLogListView.as_view(), name='vpn_reports'),
    path('security/bruteforce/', views.BruteForceListView.as_view(), name='bruteforce_dashboard'),
    path('api/stats/', views.dashboard_stats_api, name='stats_api'),
    path('api/bruteforce-stats/', views.bruteforce_stats_api, name='bruteforce_stats_api'),
    path('api/', include(router.urls)),
    path('export/pdf/', views.export_logs_pdf, name='export_pdf'),
    path('export/xlsx/', views.export_logs_xlsx, name='export_xlsx'),
]
