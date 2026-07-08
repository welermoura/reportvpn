from django.http import JsonResponse
from django.db import connection
from django.utils import timezone


def health_check(request):
    checks = {}
    overall = "ok"

    # Database
    try:
        connection.ensure_connection()
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
        checks["database"] = {"status": "ok"}
    except Exception as e:
        checks["database"] = {"status": "down", "error": str(e)}
        overall = "down"

    # Redis / Cache
    try:
        from django.core.cache import cache
        cache.set("_health_check", "1", timeout=5)
        val = cache.get("_health_check")
        if val == "1":
            checks["redis"] = {"status": "ok"}
        else:
            checks["redis"] = {"status": "degraded", "error": "cache write/read mismatch"}
            if overall == "ok":
                overall = "degraded"
    except Exception as e:
        checks["redis"] = {"status": "down", "error": str(e)}
        overall = "down"

    # Celery Beat — verifica se alguma tarefa rodou nos últimos 20 minutos
    try:
        from django_celery_beat.models import PeriodicTask
        last_run = (
            PeriodicTask.objects
            .exclude(last_run_at=None)
            .order_by("-last_run_at")
            .values_list("last_run_at", "name")
            .first()
        )
        if last_run:
            delta = timezone.now() - last_run[0]
            minutes_ago = int(delta.total_seconds() / 60)
            if delta.total_seconds() > 1200:  # 20 min
                checks["celery_beat"] = {
                    "status": "degraded",
                    "last_task": last_run[1],
                    "minutes_ago": minutes_ago,
                    "warning": "No task ran in the last 20 minutes",
                }
                if overall == "ok":
                    overall = "degraded"
            else:
                checks["celery_beat"] = {
                    "status": "ok",
                    "last_task": last_run[1],
                    "minutes_ago": minutes_ago,
                }
        else:
            checks["celery_beat"] = {"status": "degraded", "warning": "No tasks have ever run"}
            if overall == "ok":
                overall = "degraded"
    except Exception as e:
        checks["celery_beat"] = {"status": "unknown", "error": str(e)}

    status_code = 200 if overall == "ok" else (503 if overall == "down" else 200)
    return JsonResponse({"status": overall, "checks": checks}, status=status_code)
