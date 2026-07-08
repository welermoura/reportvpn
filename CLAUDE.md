# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**ReportVPN** is an enterprise Django-based SIEM/security dashboard that polls **FortiAnalyzer** (JSON-RPC) for VPN, IPS, antivirus, web filter, and app control logs, enriches them with **Active Directory** (LDAP/LDAPS) user attributes, and presents them in dashboards with risk scoring, brute force monitoring, and impossible travel detection.

## Common Commands

### Local Development
```bash
python -m venv venv
venv\Scripts\activate        # Windows
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```

### Docker (primary deployment method)
```bash
docker-compose up --build        # build and start all services
docker-compose up -d             # start detached
docker-compose logs -f web       # follow web logs
docker-compose logs -f celery    # follow worker logs
docker-compose exec web python manage.py <command>
docker-compose exec web bash
```

### Django Management
```bash
python manage.py migrate
python manage.py collectstatic --noinput
python manage.py createsuperuser
python manage.py init_admin                    # dashboard app custom command
python manage.py fetch_logs                    # vpn_logs: manual FortiAnalyzer poll
python manage.py vpn_report                    # vpn_logs: generate fidelity report
python manage.py cleanup_logs                  # vpn_logs: purge logs older than 6 months (supports --dry-run)
python manage.py fetch_security_logs           # security_events: manual poll
python manage.py setup_standard_tasks          # security_events: register Celery Beat tasks
python manage.py sync_db_config                # setup: sync .db_config.json to DB
```

### Running Tests
```bash
python manage.py test dashboard
python manage.py test vpn_logs
python manage.py test security_events
python manage.py test integrations
python manage.py test setup
python manage.py test dashboard.tests.SpecificTestCase   # single test class
```

### Utility Scripts (tools/)
```powershell
# PowerShell — must set PYTHONPATH to project root
$env:PYTHONPATH="."
python tools/backfills/run_backfill.py
```

## Architecture

### Django Apps

| App | Responsibility |
|-----|---------------|
| `dashboard` | Portal UI, VPN log views, brute force dashboard, risk score dashboard, PDF/XLSX export, access logging middleware |
| `vpn_logs` | `VPNLog` and `VPNFailure` models, FortiAnalyzer VPN polling, GeoIP enrichment, impossible travel detection |
| `security_events` | IPS/antivirus/web filter/app control events, AD auth events, RADAR AD audit (ADUser, ADGroup snapshots) |
| `integrations` | `FortiAnalyzerClient` (JSON-RPC), `ActiveDirectoryClient` (ldap3 + Redis cache), `ADLdap3Backend` (auth), singleton config models |
| `setup` | One-time database wizard (`/setup/`), `SetupRequiredMiddleware` redirects until wizard completes, writes `.db_config.json` |

### Key Architecture Decisions

**Database config is file-driven, not env-driven.** `settings.py` reads `.db_config.json` (written by the setup wizard) to choose between PostgreSQL and SQL Server. In production (`DEBUG=False`), missing config raises `ImproperlyConfigured` — there is no SQLite fallback. FA/AD credentials live in the DB as singleton models (`FortiAnalyzerConfig`, `ActiveDirectoryConfig`), not in env vars.

**Background tasks via Celery Beat.** All polling runs as Celery tasks every 10 minutes. The beat schedule is defined in `settings.py` (`CELERY_BEAT_SCHEDULE`) and also managed through `django-celery-beat` periodic tasks stored in the DB. Saving `FortiAnalyzerConfig` auto-enables/disables all polling tasks via `sync_celery_tasks()`.

**Views are split into modules** under `dashboard/views/`: `portal.py`, `logs.py`, `bruteforce.py`, `feeds.py`, `api.py`. The `__init__.py` re-exports everything so existing import paths continue to work.

**Frontend is fully offline-capable.** React, ReactDOM, Babel Standalone, Chart.js, and HTMX are served from `dashboard/static/` — no CDN calls. Babel transpiles JSX in-browser using the classic preset.

**Redis serves two roles:** Celery broker/result backend (db 0) and Django cache (db 1). AD user lookups are cached with 1-hour TTL (10 min for negatives).

**Multi-database:** PostgreSQL uses `psycopg2-binary`; SQL Server uses `mssql-django` with ODBC Driver 18, `READ UNCOMMITTED` isolation, and `CONN_MAX_AGE=0` to avoid connection pool issues in long-running Celery workers.

### Data Enrichment Pipeline

```
FortiAnalyzer JSON-RPC → Celery task → parse raw log
  → ActiveDirectoryClient.get_user_info() [Redis-cached LDAP lookup]
  → GeoIP lookup (geoip2 / MaxMind)
  → Impossible travel check (Haversine, >800 km/h = suspicious)
  → Suspicious flag (trusted_countries field on FortiAnalyzerConfig)
  → ORM save to VPNLog / SecurityEvent
```

### URL Structure

- `/` and `/portal/` — main portal (login required)
- `/vpn-reports/` — VPN log dashboard
- `/security/bruteforce/` — brute force dashboard
- `/security/risk/` — user risk score dashboard
- `/security/` — security events (IPS, antivirus, web filter, app control, AD audit)
- `/api/` — DRF routers for VPN logs, failures, risk scores, user timeline
- `/admin/` — Django admin (Jazzmin theme, dark "darkly" theme)
- `/setup/` — database setup wizard

### Middleware Order (important)

`SetupRequiredMiddleware` runs after `AuthenticationMiddleware` and redirects all requests to `/setup/` until the wizard completes. `ForcePasswordChangeMiddleware` redirects authenticated users with `profile.force_password_change=True` to the password change page.

### Design Rule

Always use images from the `inspiração/` folder as the visual reference when creating or redesigning any UI component.

## Environment Variables

Defined in `.env` (see `.env.example`). Key ones:

```ini
SECRET_KEY=...
DEBUG=False
ALLOWED_HOSTS=...
CELERY_BROKER_URL=redis://redis:6379/0
CELERY_RESULT_BACKEND=redis://redis:6379/0
REDIS_CACHE_URL=redis://redis:6379/1
HTTPS_ENABLED=False   # set True behind a reverse proxy with SSL
```

FA and AD configs are **not** read from env vars — configure them through the admin panel after setup.
