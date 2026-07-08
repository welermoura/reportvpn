import json
import pyodbc
import sys

def run_cleanup():
    try:
        with open('.db_config.json', 'r') as f:
            config = json.load(f)
    except Exception as e:
        print(f"Erro ao ler .db_config.json: {e}")
        return

    conn_str = (
        f"DRIVER={{ODBC Driver 18 for SQL Server}};"
        f"SERVER={config['host']},{config['port']};"
        f"DATABASE={config['database']};"
        f"UID={config['user']};"
        f"PWD={config['password']};"
        "TrustServerCertificate=yes;"
    )
    
    try:
        print(f"Conectando ao SQL Server em {config['host']}...")
        conn = pyodbc.connect(conn_str, autocommit=True)
        cursor = conn.cursor()
        
        # Tabelas que acumulam muito volume (Syslog legacy)
        tables_to_clear = [
            'security_events_securityevent',
            'vpn_logs_vpnlog',
            'vpn_logs_vpnfailure',
            'security_events_adauthevent'
        ]
        
        print("--- Iniciando Limpeza de Dados ---")
        for table in tables_to_clear:
            try:
                # TRUNCATE é muito mais rápido e não gera logs de transação pesados (shrink amigável)
                print(f"Limpando tabela: {table}...")
                cursor.execute(f"TRUNCATE TABLE {table}")
                print(f"OK: {table} limpa.")
            except Exception as e:
                print(f"Erro ao limpar {table} (tentando DELETE): {e}")
                try:
                    cursor.execute(f"DELETE FROM {table}")
                    print(f"OK: {table} limpa via DELETE.")
                except Exception as e2:
                    print(f"Falha total em {table}: {e2}")

        print("\n--- Iniciando Shrink do Banco de Dados (Liberação de Espaço) ---")
        print("Isso pode levar alguns minutos em volumes de 200GB...")
        
        # Shrink the database to recover space from the syslog flood
        cursor.execute(f"DBCC SHRINKDATABASE ({config['database']})")
        print("OK: DBCC SHRINKDATABASE concluído.")
        
        conn.close()
        print("\n=== Limpeza e Shrink Finalizados com Sucesso ===")
        
    except Exception as e:
        print(f"Erro de conexão ou execução: {e}")

if __name__ == "__main__":
    run_cleanup()
