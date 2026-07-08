import socket
import sys
from datetime import datetime

def send_mock_webfilter_log():
    now = datetime.now()
    date_str = now.strftime("%Y-%m-%d")
    time_str = now.strftime("%H:%M:%S")
    
    # Exemplo de log de Web Filter do FortiGate com data/hora atual para evitar deduplicação
    log = f'<189>date={date_str} time={time_str} devname="FWMTZ03" devid="FGT60ETEST" logid="0316013056" type="utm" subtype="webfilter" eventtype="ftgd_blk" level="warning" vd="root" policyid=1 sessionid=12345678 srcip="192.168.1.10" srcport=54321 srcintf="internal" srcintfrole="lan" dstip="8.8.8.8" dstport=443 dstintf="wan1" dstintfrole="wan" proto=6 service="HTTPS" hostname="www.malicious-site.com" profile="default" action="blocked" reqtype="direct" url="/" sentbyte=0 rcvdbyte=0 direction="outgoing" user="VALDIRP" group="Domain Users" authserver="LDAP" msg="URL was blocked because it is in a forbidden category" cat=26 catdesc="Malicious Websites"'
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.sendto(log.encode(), ('127.0.0.1', 5140))
        print(f"Mock WebFilter log sent to 127.0.0.1:5140 (Time: {time_str})")
    finally:
        sock.close()

if __name__ == "__main__":
    send_mock_webfilter_log()
