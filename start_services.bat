@echo off
REM Start services for VPN Dashboard

echo Starting Django Server...
start "Django Server" cmd /k "python manage.py runserver"

echo Starting Celery Worker...
start "Celery Worker" cmd /k "celery -A vpn_dashboard worker -l info --pool=solo"

echo Starting Celery Beat...
start "Celery Beat" cmd /k "celery -A vpn_dashboard beat -l info --scheduler django_celery_beat.schedulers:DatabaseScheduler"

echo All services started!
pause
