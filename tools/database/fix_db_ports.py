import os
import django

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'dashboard.settings')
django.setup()

from django.db import connection

query = """
IF COL_LENGTH('integrations_knowndevice', 'monitored_ports') IS NULL
BEGIN
    ALTER TABLE integrations_knowndevice ADD monitored_ports nvarchar(max) NULL;
    PRINT 'Coluna adicionada com sucesso.';
END
ELSE
BEGIN
    PRINT 'A coluna ja existe.';
END
"""

try:
    with connection.cursor() as cursor:
        cursor.execute(query)
    print("Execução SQL concluída via Python.")
except Exception as e:
    print(f"Erro ao executar SQL: {e}")
