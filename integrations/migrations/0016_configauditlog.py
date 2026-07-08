from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('integrations', '0015_activedirectoryconfig_ca_cert_file_and_more'),
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
    ]

    operations = [
        migrations.CreateModel(
            name='ConfigAuditLog',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('config_type', models.CharField(
                    choices=[('fortianalyzer', 'FortiAnalyzer'), ('activedirectory', 'Active Directory')],
                    max_length=30,
                    verbose_name='Configuração',
                )),
                ('changed_at', models.DateTimeField(auto_now_add=True, verbose_name='Data/Hora')),
                ('changes', models.JSONField(verbose_name='Campos Alterados')),
                ('changed_by', models.ForeignKey(
                    blank=True,
                    null=True,
                    on_delete=django.db.models.deletion.SET_NULL,
                    to=settings.AUTH_USER_MODEL,
                    verbose_name='Alterado por',
                )),
            ],
            options={
                'verbose_name': 'Log de Auditoria de Configuração',
                'verbose_name_plural': 'Logs de Auditoria de Configuração',
                'ordering': ['-changed_at'],
            },
        ),
    ]
