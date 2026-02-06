@echo off
cd /d "c:\Users\welerms\Projeto-teste"
call venv\Scripts\activate.bat 2>nul
if errorlevel 1 (
    echo Virtualenv nao encontrado no caminho padrao. Tentando rodar com python do sistema...
)

echo Iniciando coleta de logs em %date% %time%
python manage.py fetch_logs
echo Coleta finalizada em %date% %time%
pause
