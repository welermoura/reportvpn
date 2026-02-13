from django_celery_beat.apps import BeatConfig

class CustomBeatConfig(BeatConfig):
    name = 'django_celery_beat'
    verbose_name = 'Agendador de Tarefas'
