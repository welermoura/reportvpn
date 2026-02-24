import sqlite3
import datetime

def check():
    conn = sqlite3.connect('db.sqlite3')
    cursor = conn.cursor()
    
    # Lista todas as tabelas para garantir
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
    tables = [t[0] for t in cursor.fetchall()]
    print(f"Tabelas encontradas: {len(tables)}")
    
    # Procura tabelas de interesse
    t_devices = [t for t in tables if 'knowndevice' in t.lower()]
    t_events = [t for t in tables if 'securityevent' in t.lower()]
    
    print(f"Tabela Devices: {t_devices}")
    print(f"Tabela Events: {t_events}")

    if t_events:
        print("\n--- ULTIMOS 5 EVENTOS DE SEGURANÇA ---")
        try:
            cursor.execute(f"SELECT timestamp, src_ip, raw_log FROM {t_events[0]} ORDER BY timestamp DESC LIMIT 5")
            for row in cursor.fetchall():
                print(f"TS: {row[0]} | IP: {row[1]} | Raw: {row[2][:150]}...")
        except Exception as e:
            print(f"Erro ao ler eventos: {e}")

    if t_devices:
        print("\n--- STATUS DOS DISPOSITIVOS (ALTO/ALARME) ---")
        try:
            cursor.execute(f"SELECT hostname, ip_address, link_status, last_alert_message, last_seen FROM {t_devices[0]}")
            for row in cursor.fetchall():
                # Print all if they have some interesting status or just recently seen
                if row[2] != 'normal' or row[3]:
                    print(f"Host: {row[0]} | IP: {row[1]} | Status: {row[2]} | Msg: {row[3]}")
                # print recently seen
                # print(f"Seen: {row[0]} at {row[4]}")
        except Exception as e:
            print(f"Erro ao ler dispositivos: {e}")

    conn.close()

if __name__ == "__main__":
    check()
