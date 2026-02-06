# FortiAnalyzer & Active Directory Integration Platform

This project is an enterprise web application designed to centralize and visualize VPN access logs. It consumes data from the **FortiAnalyzer REST API**, enriches it with user details from **Active Directory** (via LDAP), and presents it in a modern dashboard with filtering and reporting capabilities.

## Features

- **Data Ingestion**: Automated collection of VPN logs from FortiAnalyzer.
- **Data Enrichment**: Correlation of VPN users with Active Directory attributes (Name, Department, Email).
- **Dashboard**: Interactive visualization of VPN usage.
- **Reporting**: Export functionality for audits.
- **Scheduler**: Background tasks for periodic data syncing.

## Prerequisites

- Python 3.12+
- Docker (optional, for containerized deployment)
- Access to a FortiAnalyzer instance (API)
- Access to an Active Directory server (LDAP/LDAPS)

## Setup

### 1. Environment Variables

Create a `.env` file in the root directory based on `.env.example`. Required variables include:

```ini
# Django
DEBUG=True
SECRET_KEY=your_secret_key
ALLOWED_HOSTS=localhost,127.0.0.1

# FortiAnalyzer
FA_API_URL=https://your-fortianalyzer/jsonrpc
FA_API_TOKEN=your_token
FA_ADOM=root

# Active Directory
LDAP_SERVER=ldap://your-ad-server
LDAP_USER=your_ldap_user
LDAP_PASSWORD=your_ldap_password
LDAP_SEARCH_BASE=DC=example,DC=com
```

### 2. Local Installation

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Apply migrations
python manage.py migrate

# Create superuser
python manage.py createsuperuser

# Run server
python manage.py runserver
```

### 3. Docker Deployment

```bash
# Build and run
docker-compose up --build
```

The application will be available at `http://localhost:8000`.

## Directory Structure

- `dashboard/`: Main application logic and UI.
- `integrations/`: Modules for FortiAnalyzer and Active Directory communication.
- `vpn_logs/`: Data models for storing logs.
- `scripts/`: Utility scripts for maintenance and testing (e.g., manual data sync, testing connections).
