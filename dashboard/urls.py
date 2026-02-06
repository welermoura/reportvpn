from django.urls import path
from . import views
from .views import VPNLogListView

app_name = 'dashboard'

urlpatterns = [
    path('', VPNLogListView.as_view(), name='index'),
    path('api/stats/', views.dashboard_stats_api, name='stats_api'),
    path('export/pdf/', views.export_logs_pdf, name='export_pdf'),
]
