"""Security Events URLs"""
from django.urls import path
from . import views

app_name = 'security_events'

urlpatterns = [
    path('', views.index, name='index'),
    path('ips/', views.ips_react_dashboard, name='ips'),
    path('ips-old/', views.ips_dashboard, name='ips_old'),
    path('antivirus/', views.antivirus_react_dashboard, name='antivirus'),
    path('webfilter/', views.webfilter_react_dashboard, name='webfilter'),
    path('webfilter-old/', views.webfilter_dashboard, name='webfilter_old'), # Keep old for backup if needed
    path('export/pdf/', views.export_events_pdf, name='export_pdf'),
    path('export/csv/', views.export_events_csv, name='export_csv'),
    path('export/webfilter/pdf/', views.export_webfilter_pdf, name='export_webfilter_pdf'),
    path('export/webfilter/xlsx/', views.export_webfilter_xlsx, name='export_webfilter_xlsx'),
]
