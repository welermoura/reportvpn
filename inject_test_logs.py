"""
Injeta logs de teste para cada tipo de evento UTM do FortiGate.
Executa DENTRO do container: docker-compose exec web python inject_test_logs.py
"""
import socket, datetime

SYSLOG_HOST = 'syslog_receiver'
SYSLOG_PORT = 5140

def send(msg):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.sendto(msg.encode(), (SYSLOG_HOST, SYSLOG_PORT))
    s.close()
    print(f"Sent: {msg[:100]}...")

now = datetime.datetime.now()
date_str = now.strftime("%Y-%m-%d")
time_str = now.strftime("%H:%M:%S")
# eventtime em nanoseconds
import time as t
eventtime = int(t.time() * 1e9)

base = f'devname="FWDASARIO" devid="FGT80FTK22017879" tz="-0300" eventtime={eventtime} date={date_str} time={time_str}'

# 1. IPS
send(f'<189>{base} logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" srcip="192.168.1.100" dstip="200.200.200.200" srcport="54321" dstport="443" user="joao.silva" attack="MS.SMB.Server.SMB2.TREE_CONNECT.Andx.Dos" attackid="36664" severity="critical" action="dropped" proto=6')

# 2. Antivírus
send(f'<189>{base} logid="0211008192" type="utm" subtype="virus" level="warning" vd="root" srcip="192.168.1.101" dstip="10.0.0.1" srcport="45000" dstport="80" user="maria.santos" virus="EICAR_TEST_FILE" filename="eicar.com" checksum="44d88612" action="blocked" proto=6')

# 3. WebFilter
send(f'<189>{base} logid="0317013312" type="utm" subtype="webfilter" level="notice" vd="root" srcip="192.168.1.102" dstip="151.101.1.140" srcport="58000" dstport="443" user="carlos.lima" url="https://www.reddit.com/r/gaming" catdesc="Games" action="blocked" proto=6')

# 4. App Control
send(f'<189>{base} logid="1059028704" type="utm" subtype="app-ctrl" level="notice" vd="root" srcip="192.168.1.103" dstip="17.253.144.10" srcport="60000" dstport="443" user="ana.costa" app="WhatsApp" appcat="Collaboration" apprisk="medium" sentbyte="12345" rcvdbyte="67890" action="pass" proto=6')

# 5. VPN Failure
send(f'<189>{base} logid="0101039426" type="event" subtype="vpn" level="warning" vd="root" action="ssl-login-fail" user="hacker.test" remip="45.33.32.156" reason="bad-password"')

# 6. VPN Session Up
import random
sid = f"TEST-SID-{random.randint(100000,999999)}"
send(f'<189>{base} logid="0101039424" type="event" subtype="vpn" level="notice" vd="root" action="tunnel-up" user="vpn.usuario" remip="189.115.10.20" tunnelid="{sid}" sessionid="{sid}"')

print("\nTodos os logs de teste enviados! Aguarde 3 segundos e verifique as dashboards.")
