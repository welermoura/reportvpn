from django.db import models
from cryptography.fernet import Fernet
from django.conf import settings
import os


class DatabaseConfiguration(models.Model):
    """Stores database configuration chosen during setup"""
    
    DB_TYPES = [
        ('postgresql', 'PostgreSQL'),
        ('sqlserver', 'SQL Server'),
    ]
    
    db_type = models.CharField(
        max_length=20,
        choices=DB_TYPES,
        verbose_name='Database Type'
    )
    host = models.CharField(max_length=255, verbose_name='Host')
    port = models.IntegerField(verbose_name='Port')
    database_name = models.CharField(max_length=100, verbose_name='Database Name')
    username = models.CharField(max_length=100, verbose_name='Username')
    encrypted_password = models.TextField(verbose_name='Password (Encrypted)')
    
    is_configured = models.BooleanField(default=False)
    configured_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    class Meta:
        verbose_name = 'Database Configuration'
        verbose_name_plural = 'Database Configurations'
    
    def __str__(self):
        return f"{self.get_db_type_display()} - {self.host}:{self.port}/{self.database_name}"
    
    def set_password(self, raw_password):
        """Encrypt and store password"""
        key = self._get_encryption_key()
        f = Fernet(key)
        self.encrypted_password = f.encrypt(raw_password.encode()).decode()
    
    def get_password(self):
        """Decrypt and return password"""
        key = self._get_encryption_key()
        f = Fernet(key)
        return f.decrypt(self.encrypted_password.encode()).decode()
    
    def _get_encryption_key(self):
        """Get or create encryption key"""
        key_file = os.path.join(settings.BASE_DIR, '.encryption_key')
        if os.path.exists(key_file):
            with open(key_file, 'rb') as f:
                return f.read()
        else:
            key = Fernet.generate_key()
            with open(key_file, 'wb') as f:
                f.write(key)
            return key
    
    @classmethod
    def get_active_config(cls):
        """Get the active database configuration"""
        return cls.objects.filter(is_configured=True).first()
    
    def to_dict(self):
        """Convert to dictionary for settings.py"""
        return {
            'type': self.db_type,
            'host': self.host,
            'port': self.port,
            'database': self.database_name,
            'user': self.username,
            'password': self.get_password(),
        }


class SetupProgress(models.Model):
    """Track setup wizard progress"""
    
    STEPS = [
        ('welcome', 'Welcome'),
        ('choose_db', 'Choose Database'),
        ('configure_db', 'Configure Database'),
        ('test_connection', 'Test Connection'),
        ('create_admin', 'Create Admin User'),
        ('complete', 'Complete'),
    ]
    
    current_step = models.CharField(max_length=20, choices=STEPS, default='welcome')
    is_complete = models.BooleanField(default=False)
    started_at = models.DateTimeField(auto_now_add=True)
    completed_at = models.DateTimeField(null=True, blank=True)
    
    class Meta:
        verbose_name = 'Setup Progress'
        verbose_name_plural = 'Setup Progress'
    
    def __str__(self):
        return f"Setup Progress - {self.get_current_step_display()}"
    
    @classmethod
    def get_or_create_progress(cls):
        """Get or create setup progress"""
        progress, created = cls.objects.get_or_create(
            is_complete=False,
            defaults={'current_step': 'welcome'}
        )
        return progress
