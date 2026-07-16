import time
import os

from scapy.all import sniff, conf, IFACES
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.layers.http import HTTPRequest
from scapy.layers.l2 import ARP
from scapy.layers.inet6 import IPv6
from core.analyser import Analyser as an
from core.forencic import Forensic as fo
from utils.datetime_utils import DatetimeUtils as dt
from api.utils.broadcast import broadcast


HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ",
                b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def _extract_http_payload(packet):
    """Retourne le payload brut TCP si c'est une requête HTTP."""
    if not packet.haslayer(TCP):
        return None
    raw = bytes(packet[TCP].payload)
    if not raw:
        return None
    if any(raw.startswith(m) for m in HTTP_METHODS):
        return raw
    return None


def _parse_http_path(raw_payload):
    """Extrait le path+query depuis la première ligne HTTP."""
    try:
        first_line = raw_payload.split(b"\r\n")[0].decode(errors="replace")
        parts = first_line.split(" ")
        if len(parts) >= 2:
            return parts[1]
    except Exception:
        pass
    return None


class Sniffer:
    def __init__(self, analyser_instance):
        self.analyser = analyser_instance
        self.current_iface = None

    def _get_iface(self, packet):
        iface = getattr(packet, "sniffed_on", None)
        if not iface:
            iface = self.current_iface[0] if isinstance(self.current_iface, list) else self.current_iface
        return str(iface)

    def process_packet(self, packet):
        now   = dt.get_format_now()
        iface = self._get_iface(packet)

        # ip_src / ip_dst disponibles pour tous les blocs
        ip_src = packet[IP].src if packet.haslayer(IP) else None
        ip_dst = packet[IP].dst if packet.haslayer(IP) else None

        # ===================== IP =====================
        if packet.haslayer(IP):

            if packet.haslayer(TCP):
                port_dst  = packet[TCP].dport
                tcp_flags = packet[TCP].flags
                print(f'[+]{now} TCP | {ip_src} -> {ip_dst}:{port_dst} [{tcp_flags}]')
                fo.save_captured_packet(packet=packet, iface_name=iface, protocol_name="TCP")

                broadcast("packets", {
                    "timestamp": str(now),
                    "protocol":  "TCP",
                    "ip_src":    ip_src,
                    "ip_dst":    ip_dst,
                    "port_src":  packet[TCP].sport,
                    "port_dst":  port_dst,
                    "flags":     str(tcp_flags),
                    "iface":     iface,
                })

                # Détections niveau TCP pur (basées sur les flags)
                self.analyser.detect_port_scan(ip_src, port_dst, ip_dst, tcp_flags, iface)
                self.analyser.detect_syn_flood(ip_src, port_dst, ip_dst, tcp_flags, iface)
                self.analyser.detect_os_fingerprinting(ip_src, port_dst, ip_dst, tcp_flags, iface)
                self.analyser.detect_brute_force(ip_src, port_dst, ip_dst, tcp_flags, iface)

                # Détection HTTP sur payload brut TCP
                http_raw = _extract_http_payload(packet)
                if http_raw:
                    http_path = _parse_http_path(http_raw)
                    print(f'[HTTP]{now} {ip_src} -> {ip_dst}:{port_dst} | {http_path}')

                    # SQLi / XSS sur le path + query string
                    #if http_path:
                        #self.analyser.detect_web_attack(ip_src, ip_dst, http_path, iface)

            elif packet.haslayer(UDP):
                port_dst = packet[UDP].dport
                fo.save_captured_packet(packet=packet, iface_name=iface, protocol_name="UDP")
                if port_dst == 1900:
                    print(f"[*]{now} Discovery | Appareil mobile détecté (SSDP) : {ip_src}")
                else:
                    print(f'[+]{now} UDP | {ip_src} -> {ip_dst}:{port_dst}')

                broadcast("packets", {
                    "timestamp": str(now),
                    "protocol":  "UDP",
                    "ip_src":    ip_src,
                    "ip_dst":    ip_dst,
                    "port_src":  packet[UDP].sport,
                    "port_dst":  port_dst,
                    "iface":     iface,
                })

            elif packet.haslayer(ICMP):
                code      = packet[ICMP].code
                icmp_type = packet[ICMP].type
                fo.save_captured_packet(packet=packet, iface_name=iface, protocol_name="ICMP")
                print(f'[+]{now} IPv4 (ICMP) | {ip_src} -> {ip_dst}/{code} | Ping/Echo')

                broadcast("packets", {
                    "timestamp": str(now),
                    "protocol":  "ICMP",
                    "ip_src":    ip_src,
                    "ip_dst":    ip_dst,
                    "port_src":  None,
                    "port_dst":  None,
                    "iface":     iface,
                })

                self.analyser.detect_ping_flood(ip_src, ip_dst, code, icmp_type, iface)

        # ===================== ARP =====================
        if packet.haslayer(ARP):
            arp     = packet[ARP]
            arp_src = arp.psrc
            mac_src = arp.hwsrc
            arp_dst = arp.pdst
            fo.save_captured_packet(packet=packet, iface_name=iface, protocol_name="ARP")
            print(f'[+]{now} ARP | {arp_src} ({mac_src}) -> {arp_dst}')

            broadcast("packets", {
                "timestamp": str(now),
                "protocol":  "ARP",
                "ip_src":    arp_src,
                "ip_dst":    arp_dst,
                "port_src":  None,
                "port_dst":  None,
                "mac_src":   mac_src,
                "iface":     iface,
            })

            if arp.op == 2:
                self.analyser.detect_arp_spoofing(arp_src, arp_dst, mac_src, iface)

        # ===================== IPv6 =====================
        if packet.haslayer(IPv6) and not packet.haslayer(IP):
            ipv6_src = packet[IPv6].src
            ipv6_dst = packet[IPv6].dst
            print(f'[+]{now} IPv6 Détecté | {ipv6_src} -> {ipv6_dst}')

    def get_active_interface(self):
        print("[*] Interfaces disponibles :")
        for iface_name, iface_obj in IFACES.items():
            desc = getattr(iface_obj, 'description', '') or ''
            print(f"    - {iface_name} | {desc}")

        EXCLUDE_KEYWORDS   = ["VMware", "Virtual", "Loopback", "Bluetooth", "WAN Miniport", "Direct"]
        PREFERRED_KEYWORDS = ["Wireless", "Wi-Fi", "WiFi", "Intel", "Realtek", "Ethernet"]

        for iface_name, iface_obj in IFACES.items():
            desc = getattr(iface_obj, 'description', '') or ''
            if any(kw in desc for kw in PREFERRED_KEYWORDS) and not any(kw in desc for kw in EXCLUDE_KEYWORDS):
                print(f"[*] Interface sélectionnée : {iface_name} ({desc})")
                return iface_name

        for iface_name, iface_obj in IFACES.items():
            desc = getattr(iface_obj, 'description', '') or ''
            if not any(kw in desc for kw in EXCLUDE_KEYWORDS):
                print(f"[*] Interface sélectionnée (fallback) : {iface_name} ({desc})")
                return iface_name

        print(f"[!] Fallback sur conf.iface : {conf.iface}")
        return conf.iface

    def start_sniffing(self):
        if os.path.exists('/.dockerenv'):
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
            self.current_iface = interfaces
        else:
            self.current_iface = self.get_active_interface()
            print(f"[*] Surveillance sur l'hôte : {self.current_iface}")

        while True:
            try:
                print(f'[*] Démarrage surveillance sur {self.current_iface}...')
                sniff(
                    iface=self.current_iface,
                    filter=(
                        "icmp or arp or "
                        "(tcp and not port 27017 and not port 3306 and not port 3307) or "
                        "(udp and not port 27017 and not port 3306 and not port 3307)"
                    ),
                    prn=self.process_packet,
                    store=False,
                    promisc=True
                )
            except Exception as e:
                print(f"[!] Sniffer crash : {e} — redémarrage dans 2s")
                time.sleep(2)