import json
from pathlib import Path
from django.core.management.base import BaseCommand
from setup.models import DatabaseConfiguration
from django.conf import settings

class Command(BaseCommand):
    help = 'Sincroniza a configuração do arquivo .db_config.json para o banco de dados'

    def handle(self, *args, **options):
        config_file = settings.BASE_DIR / '.db_config.json'
        
        if not config_file.exists():
            self.stdout.write(self.style.WARNING(f"Arquivo {config_file} não encontrado."))
            return

        try:
            with open(config_file, 'r') as f:
                config_data = json.load(f)
            
            # Verifica se já existe uma configuração ativa
            config, created = DatabaseConfiguration.objects.get_or_create(
                host=config_data['host'],
                database_name=config_data['database'],
                defaults={
                    'db_type': config_data['type'],
                    'port': config_data['port'],
                    'username': config_data['user'],
                    'is_configured': config_data.get('setup_complete', False),
                }
            )
            
            if created:
                # Senha precisa ser setada via método para criptografia
                config.set_password(config_data['password'])
                config.save()
                self.stdout.write(self.style.SUCCESS(f"Configuração sincronizada com sucesso para {config.host}"))
            else:
                self.stdout.write(self.style.SUCCESS(f"Configuração para {config.host} já existe no banco."))

        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Erro ao sincronizar configuração: {str(e)}"))
