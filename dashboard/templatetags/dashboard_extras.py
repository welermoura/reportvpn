from django import template

register = template.Library()

@register.simple_tag(takes_context=True)
def param_replace(context, **kwargs):
    d = context['request'].GET.copy()
    for k, v in kwargs.items():
        d[k] = v
    for k in [k for k, v in d.items() if not v]:
        del d[k]
    return d.urlencode()

@register.filter
def format_duration(seconds):
    if not seconds:
        return "-"
    try:
        seconds = int(seconds)
    except:
        return "-"
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    return f"{h:02d}:{m:02d}:{s:02d}"

@register.filter
def format_volume(bytes_val):
    if not bytes_val:
        return "-"
    try:
        bytes_val = int(bytes_val)
    except:
        return "-"
    
    gb = bytes_val / (1024 * 1024 * 1024)
    if gb >= 1:
        return f"{gb:.2f} GB"
    mb = bytes_val / (1024 * 1024)
from django.db import connection
import os

@register.simple_tag
def get_db_size():
    try:
        vendor = connection.vendor
        if vendor == 'postgresql':
            with connection.cursor() as cursor:
                cursor.execute("SELECT pg_size_pretty(pg_database_size(current_database()));")
                row = cursor.fetchone()
                if row:
                    return row[0]
        elif vendor == 'sqlite':
            db_path = connection.settings_dict.get('NAME')
            if db_path and os.path.exists(db_path):
                size_bytes = os.path.getsize(db_path)
                return format_volume(size_bytes)
        elif vendor == 'mysql':
            with connection.cursor() as cursor:
                # Retorna em MB
                cursor.execute(
                    "SELECT SUM(data_length + index_length) / 1024 / 1024 "
                    "FROM information_schema.tables WHERE table_schema = DATABASE()"
                )
                row = cursor.fetchone()
                if row and row[0]:
                    return f"{float(row[0]):.2f} MB"
        elif vendor in ('mssql', 'microsoft'):
            with connection.cursor() as cursor:
                # size column in sys.database_files is in 8-KB pages
                cursor.execute("SELECT SUM(size) * 8.0 * 1024 FROM sys.database_files")
                row = cursor.fetchone()
                if row and row[0]:
                    size_bytes = float(row[0])
                    # Reusing format_volume logic if available, or manual convert
                    if size_bytes >= 1024*1024*1024:
                        return f"{size_bytes / (1024*1024*1024):.2f} GB"
                    return f"{size_bytes / (1024*1024):.2f} MB"
                
    except Exception as e:
        print(f"Error getting db size: {e}")
        pass
    return "Desconhecido (Tamanho não suportado pelo SGBD)"
