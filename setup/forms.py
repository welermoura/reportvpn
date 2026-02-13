from django import forms
from .models import DatabaseConfiguration
import re


class DatabaseChoiceForm(forms.Form):
    """Formulário para escolher tipo de banco de dados"""
    
    db_type = forms.ChoiceField(
        choices=DatabaseConfiguration.DB_TYPES,
        widget=forms.RadioSelect,
        label='Escolha o Tipo de Banco de Dados',
        initial='postgresql'
    )


class PostgreSQLConfigForm(forms.Form):
    """Formulário para configurar PostgreSQL"""
    
    use_container = forms.BooleanField(
        required=False,
        initial=True,
        label='Usar Container Docker',
        help_text='Usar PostgreSQL em container Docker (recomendado)'
    )
    host = forms.CharField(
        max_length=255,
        initial='db',
        label='Host',
        help_text='Host do banco de dados (use "db" para container Docker)'
    )
    port = forms.IntegerField(
        initial=5432,
        label='Porta',
        help_text='Porta do banco de dados (padrão: 5432)'
    )
    database_name = forms.CharField(
        max_length=100,
        initial='vpn_siem',
        label='Nome do Banco de Dados'
    )
    username = forms.CharField(
        max_length=100,
        initial='siem_user',
        label='Usuário'
    )
    password = forms.CharField(
        widget=forms.PasswordInput,
        label='Senha',
        min_length=8
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput,
        label='Confirmar Senha'
    )
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        
        if password and password_confirm and password != password_confirm:
            raise forms.ValidationError('As senhas não coincidem')
        
        return cleaned_data


class SQLServerConfigForm(forms.Form):
    """Formulário para configurar SQL Server"""
    
    host = forms.CharField(
        max_length=255,
        label='Host do SQL Server',
        help_text='Nome do host ou endereço IP do SQL Server'
    )
    port = forms.IntegerField(
        initial=1433,
        label='Porta',
        help_text='Porta do SQL Server (padrão: 1433)'
    )
    database_name = forms.CharField(
        max_length=100,
        initial='VPN_SIEM',
        label='Nome do Banco de Dados',
        help_text='O banco de dados será criado se não existir'
    )
    username = forms.CharField(
        max_length=100,
        label='Usuário do SQL Server',
        help_text='Usuário deve ter permissão CREATE DATABASE'
    )
    password = forms.CharField(
        widget=forms.PasswordInput,
        label='Senha'
    )
    use_windows_auth = forms.BooleanField(
        required=False,
        initial=False,
        label='Usar Autenticação Windows',
        help_text='Usar Autenticação Windows em vez de autenticação SQL Server'
    )
    
    def clean_database_name(self):
        """Validar nome do banco de dados para SQL Server"""
        db_name = self.cleaned_data.get('database_name')
        
        # Regras de nome de banco SQL Server
        if not re.match(r'^[a-zA-Z_][a-zA-Z0-9_@$#]*$', db_name):
            raise forms.ValidationError(
                'O nome do banco deve começar com uma letra ou underscore e '
                'conter apenas letras, números, @, $, # ou _'
            )
        
        if len(db_name) > 128:
            raise forms.ValidationError('O nome do banco deve ter no máximo 128 caracteres')
        
        # Palavras reservadas
        reserved = ['master', 'model', 'msdb', 'tempdb']
        if db_name.lower() in reserved:
            raise forms.ValidationError(f'"{db_name}" é um nome de banco reservado')
        
        return db_name


class AdminUserForm(forms.Form):
    """Formulário para criar usuário administrador"""
    
    username = forms.CharField(
        max_length=150,
        label='Nome de Usuário Admin',
        help_text='Nome de usuário para a conta de administrador'
    )
    email = forms.EmailField(
        label='Endereço de Email',
        help_text='Email do administrador'
    )
    password = forms.CharField(
        widget=forms.PasswordInput,
        label='Senha',
        min_length=8,
        help_text='Mínimo de 8 caracteres'
    )
    password_confirm = forms.CharField(
        widget=forms.PasswordInput,
        label='Confirmar Senha'
    )
    
    def clean_username(self):
        """Validar nome de usuário"""
        username = self.cleaned_data.get('username')
        
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            raise forms.ValidationError(
                'O nome de usuário pode conter apenas letras, números e underscores'
            )
        
        return username
    
    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        
        if password and password_confirm and password != password_confirm:
            raise forms.ValidationError('As senhas não coincidem')
        
        return cleaned_data
