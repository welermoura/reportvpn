
import os
import sys
import django
import requests

# Configurar ambiente Django
sys.path.append('c:\\Users\\welerms\\Projeto-teste')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'vpn_dashboard.settings') # Ajuste provável, confirmo ao ver manage.py
django.setup()

from integrations.models import FortiAnalyzerConfig, ActiveDirectoryConfig
from integrations.fortianalyzer import FortiAnalyzerClient
# from integrations.ad import ActiveDirectoryClient # Assumindo que existe tal classe baseada em fortianalyzer.py

def check_fortianalyzer():
    print("\n[FortiAnalyzer] Iniciando teste de conexão...", flush=True)
    try:
        config = FortiAnalyzerConfig.load()
        if not config.host:
            print("[FortiAnalyzer] ERRO: Host não configurado.", flush=True)
            return

        client = FortiAnalyzerClient()
        print(f"[FortiAnalyzer] Conectando a {config.host}:{config.port}...", flush=True)
        
        try:
            logs = client.get_logs(limit=1)
            # Se authenticated, o FA deve retornar um JSON valido (mesmo que seja erro de permissao da API, conexao OK)
            if logs is not None:
                print(f"[FortiAnalyzer] SUCESSO! Resposta recebida. (Tipo: {type(logs)})", flush=True)
                print(f"[FortiAnalyzer] OK", flush=True)
            else:
                print("[FortiAnalyzer] FALHA: A função retornou None.", flush=True)
        except Exception as e:
            print(f"[FortiAnalyzer] EXCEÇÃO durante requisição: {e}", flush=True)

    except Exception as e:
        print(f"[FortiAnalyzer] ERRO GERAL: {e}", flush=True)

def check_ad():
    print("\n[Active Directory] Iniciando teste de conexão...", flush=True)
    try:
        config = ActiveDirectoryConfig.load()
        if not config.server:
            print("[Active Directory] ERRO: Servidor não configurado.", flush=True)
            return

        print(f"[Active Directory] Servidor: {config.server}:{config.port} (SSL: {config.use_ssl})", flush=True)
        print(f"[Active Directory] Bind User: {config.bind_user}", flush=True)
        
        try:
            from integrations.ad import ActiveDirectoryClient
            print("[Active Directory] Classe ActiveDirectoryClient encontrada.", flush=True)
        except ImportError:
            print("[Active Directory] Classe 'ActiveDirectoryClient' ausente. Testando via ldap3 direto.", flush=True)
            try:
                import ldap3
                from ldap3 import Server, Connection, ALL, NTLM
                
                print(f"[Active Directory] Versão ldap3: {ldap3.__version__}", flush=True)
                
                server = Server(config.server, port=config.port, get_info=ALL)
                print(f"[Active Directory] Tentando bind com usuário: {config.bind_user}", flush=True)
                
                conn = Connection(server, user=config.bind_user, password=config.bind_password, auto_bind=True)
                print(f"[Active Directory] SUCESSO! Conexão estabelecida.", flush=True)
                print(f"[Active Directory] Who am I: {conn.extend.standard.who_am_i()}", flush=True)
            except Exception as e:
                print(f"[Active Directory] FALHA no teste LDAP: {e}", flush=True)
                import traceback
                traceback.print_exc()

    except Exception as e:
        print(f"[Active Directory] ERRO GERAL: {e}", flush=True)

if __name__ == "__main__":
    check_fortianalyzer()
    check_ad()
