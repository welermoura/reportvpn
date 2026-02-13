from django.urls import path
from . import views

app_name = 'setup'

urlpatterns = [
    path('', views.WelcomeView.as_view(), name='welcome'),
    path('choose-database/', views.ChooseDatabaseView.as_view(), name='choose_database'),
    path('configure-postgresql/', views.ConfigurePostgreSQLView.as_view(), name='configure_postgresql'),
    path('configure-sqlserver/', views.ConfigureSQLServerView.as_view(), name='configure_sqlserver'),
    path('test-connection/', views.TestConnectionView.as_view(), name='test_connection'),
    path('create-admin/', views.CreateAdminView.as_view(), name='create_admin'),
    path('complete/', views.CompleteView.as_view(), name='complete'),
]
