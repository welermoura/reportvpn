
from django.contrib import admin
from django.contrib.auth.models import Group, User
from django_celery_beat.models import (
    PeriodicTask, IntervalSchedule, CrontabSchedule, 
    SolarSchedule, ClockedSchedule, PeriodicTasks
)
from django_celery_beat.admin import PeriodicTaskAdmin, PeriodicTaskForm, TaskChoiceField
from django import forms
from django.utils.translation import gettext_lazy as _

# Unregister default django-celery-beat admins
try:
    admin.site.unregister(PeriodicTask)
    admin.site.unregister(IntervalSchedule)
    admin.site.unregister(CrontabSchedule)
    admin.site.unregister(SolarSchedule)
    admin.site.unregister(ClockedSchedule)
except admin.sites.NotRegistered:
    pass


# Custom Forms with Portuguese Labels
class CustomPeriodicTaskForm(PeriodicTaskForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['regtask'].label = "Tarefa (registrada)"
        self.fields['task'].label = "Tarefa (personalizada)"
        
    class Meta:
        model = PeriodicTask
        exclude = ()

# Custom Admins with Portuguese Fieldsets
@admin.register(PeriodicTask)
class CustomPeriodicTaskAdmin(PeriodicTaskAdmin):
    form = CustomPeriodicTaskForm
    fieldsets = (
        (None, {
            'fields': ('name', 'regtask', 'task', 'enabled', 'description',),
            'classes': ('extrapretty', 'wide'),
        }),
        ('Agendamento', {
            'fields': ('interval', 'crontab', 'solar',
                       'clocked', 'start_time', 'last_run_at', 'one_off'),
            'classes': ('extrapretty', 'wide'),
        }),
        ('Argumentos', {
            'fields': ('args', 'kwargs'),
            'classes': ('extrapretty', 'wide', 'collapse', 'in'),
        }),
        ('Opções de Execução', {
            'fields': ('expires', 'expire_seconds', 'queue', 'exchange',
                       'routing_key', 'priority', 'headers'),
            'classes': ('extrapretty', 'wide', 'collapse', 'in'),
        }),
    )

@admin.register(IntervalSchedule)
class CustomIntervalScheduleAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'period', 'every')
    verbose_name = "Intervalo"

@admin.register(CrontabSchedule)
class CustomCrontabScheduleAdmin(admin.ModelAdmin):
    list_display = ('__str__', 'human_readable')
    verbose_name = "Agendamento Crontab"

@admin.register(SolarSchedule)
class CustomSolarScheduleAdmin(admin.ModelAdmin):
    pass

@admin.register(ClockedSchedule)
class CustomClockedScheduleAdmin(admin.ModelAdmin):
    pass

from .models import PortalModule

@admin.register(PortalModule)
class PortalModuleAdmin(admin.ModelAdmin):
    list_display = ('title', 'slug', 'is_active', 'order', 'url_name')
    list_editable = ('is_active', 'order')
    prepopulated_fields = {'slug': ('title',)}
    search_fields = ('title', 'slug', 'description')
    ordering = ('order',)
