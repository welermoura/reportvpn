# Usar uma imagem base oficial do Python
FROM python:3.12-slim

# Definir variáveis de ambiente para evitar arquivos .pyc e logs em buffer
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Definir diretório de trabalho
WORKDIR /app

# Instalar dependências do sistema necessárias para LDAP, ODBC e outros
RUN apt-get update && apt-get install -y \
    build-essential \
    libldap2-dev \
    libsasl2-dev \
    libssl-dev \
    pkg-config \
    libcairo2-dev \
    libpango1.0-dev \
    gcc \
    postgresql-client \
    curl \
    gnupg2 \
    apt-transport-https \
    unixodbc-dev \
    && curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
    && curl -fsSL https://packages.microsoft.com/config/debian/12/prod.list > /etc/apt/sources.list.d/mssql-release.list \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y msodbcsql18 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Copiar requirements e instalar dependências Python
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiar o projeto
COPY . .
RUN chmod +x /app/scripts/entrypoint.sh

# Collect static files
RUN python manage.py collectstatic --noinput

# Expor a porta 8000
EXPOSE 8000

# Comando padrão (pode ser sobrescrito pelo docker-compose)
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "--workers", "3", "vpn_dashboard.wsgi:application"]
