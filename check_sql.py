import pyodbc
import json
import os

def check_sql_direct():
    # Carregar config do .db_config.json
    config_path = '.db_config.json'
    if not os.path.exists(config_path):
        print(f"Erro: {config_path} não encontrado.")
        return

    with open(config_path, 'r') as f:
        db_config = json.load(f)

    conn_str = (
        f"DRIVER={{ODBC Driver 18 for SQL Server}};"
        f"SERVER={db_config['host']},{db_config['port']};"
        f"DATABASE={db_config['name']};"
        f"UID={db_config['user']};"
        f"PWD={db_config['password']};"
        f"TrustServerCertificate=yes;"
    )

    print(f"Conectando ao SQL Server: {db_config['host']}...")
    try:
        conn = pyodbc.connect(conn_str)
        cursor = conn.cursor()
        
        print("\n--- TABLES ---")
        cursor.execute("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_TYPE = 'BASE TABLE'")
        for row in cursor.fetchall():
            print(row[0])
            
        print("\n--- ROW COUNT ---")
        try:
            cursor.execute("SELECT COUNT(*) FROM vpn_logs_vpnlog")
            count = cursor.fetchone()[0]
            print(f"Linhas em vpn_logs_vpnlog: {count}")
        except Exception as e:
            print(f"Erro ao contar vpn_logs_vpnlog: {e}")

        conn.close()
    except Exception as e:
        print(f"Erro de conexão: {e}")

if __name__ == "__main__":
    check_sql_direct()
