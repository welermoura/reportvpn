import socket
import time
from datetime import datetime

def send_vpn_failure():
    # USAR UM IP QUE NÃO SEJA 0.0.0.0 PARA TESTAR GEOIP (ex: IP do Google)
    target_ip = "8.8.8.8" 
    # USER QUE APARECEU NO LOG RECENTE
    target_user = "MARIANATSMA"
    
    # Formato Syslog Fortinet para VPN Failure
    # date=2026-02-25 time=11:20:00 devname="FGT-BR-VIC" devid="FGT60E4Q16000000" logid="0101037131" type="event" subtype="vpn" level="notice" vd="root" eventtime=1646241600000000000 logdesc="SSL VPN login fail" action="ssl-login-fail" user="MARIANATSMA" remip="8.8.8.8" reason="ssl-login-fail" msg="SSL VPN login fail"
    
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_msg = f'<189>date=2026-02-25 time={datetime.now().strftime("%H:%M:%S")} devname="FGT-BR-VIC" devid="FGT60E4Q16000000" logid="0101037131" type="event" subtype="vpn" level="notice" vd="root" logdesc="SSL VPN login fail" action="ssl-login-fail" user="{target_user}" remip="{target_ip}" reason="ssl-login-fail" msg="SSL VPN login fail"'
    
    print(f"Enviando log: {log_msg}")
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.sendto(log_msg.encode(), ("127.0.0.1", 5140))
    print("Log enviado para 127.0.0.1:5140")

if __name__ == "__main__":
    send_vpn_failure()
