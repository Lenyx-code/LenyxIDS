#!/usr/bin/env python3
"""
Port Scan réel via socket — détecté par le sniffer
Attaquant : 172.19.0.4  →  Victime : 172.19.0.3
"""

import socket
import time
import sys
import threading

ATTACKER_IP = "172.19.0.4"
VICTIM_IP   = "172.19.0.3"

PORTS = [
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139,
    143, 443, 445, 993, 995, 1723, 3306, 3389,
    5900, 8080, 8443, 8888
]

def scan_port(ip, port):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.3)
        s.connect((ip, port))
        s.close()
        print(f"  [→] SYN envoyé vers {ip}:{port} [OUVERT]")
    except:
        print(f"  [→] SYN envoyé vers {ip}:{port} [fermé]")

def port_scan(target_ip, ports, delay=0.05):
    print(f"\n[*] Démarrage Port Scan SYN")
    print(f"[*] Source      : {ATTACKER_IP}")
    print(f"[*] Cible       : {target_ip}")
    print(f"[*] Ports       : {len(ports)} ports")
    print("-" * 50)

    for port in ports:
        scan_port(target_ip, port)
        time.sleep(delay)

    print("-" * 50)
    print(f"[✓] Scan terminé — {len(ports)} ports scannés sur {target_ip}")

if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else VICTIM_IP
    port_scan(target, PORTS)