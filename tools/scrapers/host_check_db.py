import sqlite3
import datetime

def check():
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    
    print("--- ULTIMOS 5 EVENTOS DE SEGURANÇA ---")
    try:
        cursor.execute("SELECT timestamp, src_ip, raw_log FROM security_events_securityevent ORDER BY timestamp DESC LIMIT 5")
        for row in cursor.fetchall():
            print(f"TS: {row[0]} | IP: {row[1]} | Raw: {row[2][:150]}...")
    except Exception as e:
        print(f"Erro ao ler eventos: {e}")

    print("\n--- STATUS DOS DISPOSITIVOS (LINK ATIVO) ---")
    try:
        cursor.execute("SELECT hostname, ip_address, link_status, last_alert_message FROM integrations_knowndevice WHERE link_status != 'normal' OR last_alert_message IS NOT NULL")
        for row in cursor.fetchall():
            print(f"Host: {row[0]} | IP: {row[1]} | Status: {row[2]} | Msg: {row[3]}")
    except Exception as e:
        print(f"Erro ao ler dispositivos: {e}")

    conn.close()

if __name__ == "__main__":
    check()
