from scapy.all import sniff, conf, IFACES, wrpcap
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IPv6
from scapy.layers.http import HTTP
from core.analyser import Analyser as an
from utils.datetime_utils import DatetimeUtils as dt
import os


class Sniffer:
    def __init__(self, analyser_instance):
        self.analyser = analyser_instance
    
    def process_packet(self, packet):
        now = dt.get_format_now()
        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            
            port_dst = None
            tcp_flags = None

            if packet.haslayer(TCP):
                port_dst = packet[TCP].dport 
                tcp_flags = packet[TCP].flags
                print(f'[+]{now} TCP | {ip_src} -> {ip_dst}:{port_dst} [{tcp_flags}]')
                
                self.analyser.detect_port_scan(ip_src, port_dst, ip_dst, tcp_flags)
                self.analyser.detect_brute_force(ip_src, port_dst, ip_dst, tcp_flags)
                self.analyser.detect_syn_flood(ip_src, port_dst, ip_dst, tcp_flags)
                self.analyser.detect_os_fingerprinting(ip_src, port_dst, ip_dst, tcp_flags)
                
            elif packet.haslayer(UDP):
                port_dst = packet[UDP].dport
                print(f'[+]{now} UDP | {ip_src} -> {ip_dst}:{port_dst}')

            elif packet.haslayer(UDP) and packet[UDP].dport == 1900:
                print(f"[*]{now} Discovery | Appareil mobile détecté (SSDP) : {ip_src}")
            
            elif packet.haslayer(ICMP):
                code = packet[ICMP].code
                print(f'[+]{now} IPv4 (ICMP) | {ip_src} -> {ip_dst}/{code} | Ping/Echo')

            
            
        if packet.haslayer(ARP):
            arp = packet[ARP]
            ip_src  = arp.psrc
            mac_src = arp.hwsrc
            ip_dst  = arp.pdst 
            print(f'[+]{now} ARP | {ip_src} ({mac_src}) -> {ip_dst}')
            if arp.op == 2:
                self.analyser.detect_arp_spoofing(ip_src, ip_dst, mac_src)


        # Gestion IPv6
        elif packet.haslayer(IPv6):
            ipv6_src = packet[IPv6].src
            ipv6_dst = packet[IPv6].dst
            print(f'[+]{now} IPv6 Detecté | {ipv6_src} -> {ipv6_dst}')

    #Réccupération dses interfaces actives
    def get_active_interface(self):
        print("[*] Interfaces disponibles :")
        for iface_name, iface_obj in IFACES.items():
            desc = getattr(iface_obj, 'description', '') or ''
            print(f"    - {iface_name} | {desc}")

        # exclusions des cartes virtuelles 
        EXCLUDE_KEYWORDS = ["VMware", "Virtual", "Loopback", "Bluetooth", "WAN Miniport", "Direct"]
        PREFERRED_KEYWORDS = ["Wireless", "Wi-Fi", "WiFi", "Intel", "Realtek", "Ethernet"]

        best_iface = None

        
        for iface_name, iface_obj in IFACES.items():
            desc = getattr(iface_obj, 'description', '') or ''
            is_virtual = any(kw in desc for kw in EXCLUDE_KEYWORDS)
            is_preferred = any(kw in desc for kw in PREFERRED_KEYWORDS)
            if is_preferred and not is_virtual:
                best_iface = iface_name
                print(f"[*] Interface sélectionnée : {iface_name} ({desc})")
                return best_iface

        for iface_name, iface_obj in IFACES.items():
            desc = getattr(iface_obj, 'description', '') or ''
            is_virtual = any(kw in desc for kw in EXCLUDE_KEYWORDS)
            if not is_virtual:
                best_iface = iface_name
                print(f"[*] Interface sélectionnée (fallback) : {iface_name} ({desc})")
                return best_iface

        print(f"[!] Fallback sur conf.iface : {conf.iface}")
        return conf.iface

    def start_sniffing(self):
        if os.path.exists('/.dockerenv'):
            # Détecter toutes les interfaces actives sauf loopback
            import subprocess
            result = subprocess.run(
                ["ip", "-o", "link", "show", "up"],
                capture_output=True, text=True
            )
            interfaces = []
            for line in result.stdout.splitlines():
                iface = line.split(":")[1].strip().split("@")[0]
                if iface != "lo":
                    interfaces.append(iface)

            if not interfaces:
                interfaces = ["eth0"]

            print(f"[*] Environnement Docker détecté. Interfaces : {interfaces}")
            interface_to_use = interfaces
        else:
            interface_to_use = self.get_active_interface()
            print(f"[*] Surveillance sur : {interface_to_use}")

        print(f'[*] Démarrage surveillance sur {interface_to_use}...')

        sniff(
            iface=interface_to_use,
            filter="ip or arp",
            prn=self.process_packet,
            store=False,
            promisc=True
        )