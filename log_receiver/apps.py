from django.apps import AppConfig

class LogReceiverConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'log_receiver'
    verbose_name = 'Syslog Receiver'
