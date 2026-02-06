#!/bin/bash

# Falhar em caso de erro
set -e

echo "Iniciando Entrypoint..."

# Aplicar migrações
echo "Aplicando migrações do banco de dados..."
python manage.py migrate --noinput

# Criar superusuário padrão (admin/admin) se não existir
echo "Verificando superusuário..."
python manage.py init_admin || echo "Erro ao criar admin ou já existe."

# Executar o comando passado (geralmente start)
# Se nenhum comando for passado, usa o padrão
if [ "$#" -eq 0 ]; then
    echo "Coletando arquivos estáticos..."
    python manage.py collectstatic --noinput

    echo "Iniciando servidor Gunicorn..."
    exec gunicorn vpn_dashboard.wsgi:application --bind 0.0.0.0:8000 --workers 3
else
    exec "$@"
fi
