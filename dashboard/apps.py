from django.apps import AppConfig



class DashboardConfig(AppConfig):
    name = 'dashboard'
    verbose_name = 'Dashboard'

    def ready(self):
        import dashboard.signals
        
        # Monkey-patch verbose names for django_celery_beat models
        try:
            from django.apps import apps
            from django.db.models.signals import post_migrate
            
            def configure_celery_beat_names(sender, **kwargs):
                try:
                    # PeriodicTask Translations
                    PeriodicTask = apps.get_model('django_celery_beat', 'PeriodicTask')
                    PeriodicTask._meta.verbose_name = "Tarefa Agendada"
                    PeriodicTask._meta.verbose_name_plural = "Tarefas Agendadas"
                    
                    # Fields
                    PeriodicTask._meta.get_field('name').verbose_name = "Nome"
                    PeriodicTask._meta.get_field('name').help_text = "Descrição curta para esta tarefa"
                    
                    PeriodicTask._meta.get_field('task').verbose_name = "Tarefa (registrada)"
                    PeriodicTask._meta.get_field('task').help_text = "Exemplo: app.tasks.minha_tarefa"
                    
                    PeriodicTask._meta.get_field('interval').verbose_name = "Intervalo"
                    PeriodicTask._meta.get_field('crontab').verbose_name = "Agendamento Crontab"
                    PeriodicTask._meta.get_field('solar').verbose_name = "Agendamento Solar"
                    PeriodicTask._meta.get_field('clocked').verbose_name = "Agendamento Pontual"
                    
                    PeriodicTask._meta.get_field('enabled').verbose_name = "Habilitado"
                    PeriodicTask._meta.get_field('enabled').help_text = "Desmarque para desativar o agendamento"
                    
                    PeriodicTask._meta.get_field('description').verbose_name = "Descrição"
                    PeriodicTask._meta.get_field('description').help_text = "Descrição detalhada desta tarefa agendada"
                    
                    PeriodicTask._meta.get_field('start_time').verbose_name = "Data de Início"
                    PeriodicTask._meta.get_field('last_run_at').verbose_name = "Última Execução"
                    PeriodicTask._meta.get_field('total_run_count').verbose_name = "Total de Execuções"
                    PeriodicTask._meta.get_field('one_off').verbose_name = "Execução Única"


                    # IntervalSchedule Translations
                    IntervalSchedule = apps.get_model('django_celery_beat', 'IntervalSchedule')
                    IntervalSchedule._meta.verbose_name = "Intervalo"
                    IntervalSchedule._meta.verbose_name_plural = "Intervalos"
                    
                    IntervalSchedule._meta.get_field('every').verbose_name = "A cada"
                    IntervalSchedule._meta.get_field('period').verbose_name = "Período"


                    # CrontabSchedule Translations
                    CrontabSchedule = apps.get_model('django_celery_beat', 'CrontabSchedule')
                    CrontabSchedule._meta.verbose_name = "Agendamento Crontab"
                    CrontabSchedule._meta.verbose_name_plural = "Agendamentos Crontab"
                    
                    CrontabSchedule._meta.get_field('minute').verbose_name = "Minuto"
                    CrontabSchedule._meta.get_field('hour').verbose_name = "Hora"
                    CrontabSchedule._meta.get_field('day_of_week').verbose_name = "Dia da Semana"
                    CrontabSchedule._meta.get_field('day_of_month').verbose_name = "Dia do Mês"
                    CrontabSchedule._meta.get_field('month_of_year').verbose_name = "Mês do Ano"


                    SolarSchedule = apps.get_model('django_celery_beat', 'SolarSchedule')
                    SolarSchedule._meta.verbose_name = "Agendamento Solar"
                    SolarSchedule._meta.verbose_name_plural = "Agendamentos Solares"

                    ClockedSchedule = apps.get_model('django_celery_beat', 'ClockedSchedule')
                    ClockedSchedule._meta.verbose_name = "Agendamento Pontual"
                    ClockedSchedule._meta.verbose_name_plural = "Agendamentos Pontuais"
                    
                    ClockedSchedule._meta.get_field('clocked_time').verbose_name = "Hora Marcada"
                    
                except Exception as e:
                    pass

            post_migrate.connect(configure_celery_beat_names, sender=self)
            # Also run immediately in case migration is already done
            configure_celery_beat_names(None)
            
        except ImportError:
            pass
