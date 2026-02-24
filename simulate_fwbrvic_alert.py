import socket
import time

TARGET_IP = "127.0.0.1"
TARGET_PORT = 5140
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

def send_log(msg):
    sock.sendto(msg.encode(), (TARGET_IP, TARGET_PORT))
    print(f"Sent: {msg[:100]}...")

# Log do FWBRVIC (10.120.1.54) - FGT60FTK2109DB7G
# Reportando Internal3 DOWN
log_failing = '<189>date=2026-02-24 time=14:35:00 devname="FWBRVIC" devid="FGT60FTK2109DB7G" logid="0100022921" type="event" subtype="sdwan" level="warning" vd="root" logdesc="SD-WAN health-check member changed state" msg="SD-WAN health-check member changed state" member="Internal3" status="down"'

print("Enviando simulação de falha para FWBRVIC...")
send_log(log_failing)
sock.close()
