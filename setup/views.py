from django.shortcuts import render, redirect
from django.views import View
from django.contrib.auth.models import User
from django.conf import settings
from django.core.management import call_command
from .forms import DatabaseChoiceForm, PostgreSQLConfigForm, SQLServerConfigForm, AdminUserForm
from .models import DatabaseConfiguration, SetupProgress
from .utils import (
    test_postgresql_connection,
    test_sqlserver_connection,
    create_postgresql_database,
    create_sqlserver_database,
    save_database_config,
    is_setup_complete
)
import json


class WelcomeView(View):
    """Welcome page for setup wizard"""
    
    def get(self, request):
        # Check if already configured
        if is_setup_complete(settings.BASE_DIR):
            return redirect('dashboard:index')
        
        progress = SetupProgress.get_or_create_progress()
        return render(request, 'setup/welcome.html', {'progress': progress})
    
    def post(self, request):
        progress = SetupProgress.get_or_create_progress()
        progress.current_step = 'choose_db'
        progress.save()
        return redirect('setup:choose_database')


class ChooseDatabaseView(View):
    """Choose database type"""
    
    def get(self, request):
        form = DatabaseChoiceForm()
        return render(request, 'setup/choose_database.html', {'form': form})
    
    def post(self, request):
        form = DatabaseChoiceForm(request.POST)
        if form.is_valid():
            db_type = form.cleaned_data['db_type']
            request.session['db_type'] = db_type
            
            if db_type == 'postgresql':
                return redirect('setup:configure_postgresql')
            else:
                return redirect('setup:configure_sqlserver')
        
        return render(request, 'setup/choose_database.html', {'form': form})


class ConfigurePostgreSQLView(View):
    """Configure PostgreSQL"""
    
    def get(self, request):
        form = PostgreSQLConfigForm()
        return render(request, 'setup/configure_postgresql.html', {'form': form})
    
    def post(self, request):
        form = PostgreSQLConfigForm(request.POST)
        if form.is_valid():
            # Save configuration to session
            request.session['db_config'] = {
                'type': 'postgresql',
                'host': form.cleaned_data['host'],
                'port': form.cleaned_data['port'],
                'database': form.cleaned_data['database_name'],
                'user': form.cleaned_data['username'],
                'password': form.cleaned_data['password'],
                'use_container': form.cleaned_data['use_container'],
            }
            return redirect('setup:test_connection')
        
        return render(request, 'setup/configure_postgresql.html', {'form': form})


class ConfigureSQLServerView(View):
    """Configure SQL Server"""
    
    def get(self, request):
        form = SQLServerConfigForm()
        return render(request, 'setup/configure_sqlserver.html', {'form': form})
    
    def post(self, request):
        form = SQLServerConfigForm(request.POST)
        if form.is_valid():
            # Save configuration to session
            request.session['db_config'] = {
                'type': 'sqlserver',
                'host': form.cleaned_data['host'],
                'port': form.cleaned_data['port'],
                'database': form.cleaned_data['database_name'],
                'user': form.cleaned_data['username'],
                'password': form.cleaned_data['password'],
                'windows_auth': form.cleaned_data['use_windows_auth'],
            }
            return redirect('setup:test_connection')
        
        return render(request, 'setup/configure_sqlserver.html', {'form': form})


class TestConnectionView(View):
    """Test database connection"""
    
    def get(self, request):
        db_config = request.session.get('db_config')
        if not db_config:
            return redirect('setup:choose_database')
        
        return render(request, 'setup/test_connection.html', {'db_config': db_config})
    
    def post(self, request):
        db_config = request.session.get('db_config')
        if not db_config:
            return redirect('setup:choose_database')
        
        # Test connection
        if db_config['type'] == 'postgresql':
            success, message = test_postgresql_connection(
                db_config['host'],
                db_config['port'],
                db_config['database'],
                db_config['user'],
                db_config['password']
            )
        else:
            success, message = test_sqlserver_connection(
                db_config['host'],
                db_config['port'],
                db_config['database'],
                db_config['user'],
                db_config['password'],
                db_config.get('windows_auth', False)
            )
        
        if success:
            # Create database if needed
            if db_config['type'] == 'postgresql':
                create_success, create_msg = create_postgresql_database(
                    db_config['host'],
                    db_config['port'],
                    db_config['user'],
                    db_config['password'],
                    db_config['database']
                )
            else:
                create_success, create_msg = create_sqlserver_database(
                    db_config['host'],
                    db_config['port'],
                    db_config['user'],
                    db_config['password'],
                    db_config['database'],
                    db_config.get('windows_auth', False)
                )
            
            if create_success:
                # Save configuration
                save_database_config(db_config, settings.BASE_DIR)
                
                # Run migrations automatically to create all tables
                try:
                    call_command('migrate', '--noinput')
                    migration_success = True
                    migration_message = "Todas as tabelas do banco de dados foram criadas com sucesso"
                except Exception as e:
                    migration_success = False
                    migration_message = f"Erro ao criar tabelas: {str(e)}"
                    return render(request, 'setup/test_connection.html', {
                        'db_config': db_config,
                        'error': migration_message
                    })
                
                return redirect('setup:create_admin')
            else:
                return render(request, 'setup/test_connection.html', {
                    'db_config': db_config,
                    'error': create_msg
                })
        else:
            return render(request, 'setup/test_connection.html', {
                'db_config': db_config,
                'error': message
            })


class CreateAdminView(View):
    """Create admin user"""
    
    def get(self, request):
        form = AdminUserForm()
        return render(request, 'setup/create_admin.html', {'form': form})
    
    def post(self, request):
        form = AdminUserForm(request.POST)
        if form.is_valid():
            # Create superuser
            try:
                user = User.objects.create_superuser(
                    username=form.cleaned_data['username'],
                    email=form.cleaned_data['email'],
                    password=form.cleaned_data['password']
                )
                
                # Mark setup as complete
                db_config = request.session.get('db_config', {})
                db_config['setup_complete'] = True
                save_database_config(db_config, settings.BASE_DIR)
                
                # Update progress
                progress = SetupProgress.get_or_create_progress()
                progress.is_complete = True
                progress.current_step = 'complete'
                progress.save()
                
                return redirect('setup:complete')
            except Exception as e:
                return render(request, 'setup/create_admin.html', {
                    'form': form,
                    'error': str(e)
                })
        
        return render(request, 'setup/create_admin.html', {'form': form})


class CompleteView(View):
    """Setup complete"""
    
    def get(self, request):
        return render(request, 'setup/complete.html')
