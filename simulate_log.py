import socket
import sys

# IP do servidor docker ou localhost
TARGET_IP = "127.0.0.1"
TARGET_PORT = 5140

# Log de simulação idêntico ao formato FortiGate
msg = '<189>date=2026-02-24 time=10:35:00 devname="FW-FILIAL" devid="FGT60FTK2109DB7G" logid="0100022921" type="event" subtype="sdwan" level="warning" vd="root" logdesc="Link monitor status" msg="Link Monitor: wan2 status is down"'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    sock.sendto(msg.encode(), (TARGET_IP, TARGET_PORT))
    print(f"✅ Pacote enviado com sucesso para {TARGET_IP}:{TARGET_PORT}")
except Exception as e:
    print(f"❌ Erro ao enviar pacote: {e}")
finally:
    sock.close()
