from utils.datetime_utils import DatetimeUtils as dt
from scapy.layers.http import HTTPRequest
from database.mongodb.models.alert import *
from database.mongodb.repository import Repository
import time
import os
from api.utils.broadcast import broadcast

try:
    from libinjection import is_sql_injection, is_xss
    LIBINJECTION_AVAILABLE = True
except ImportError:
    LIBINJECTION_AVAILABLE = False
    print("[!] libinjection non installé — détection SQLi/XSS désactivée")

port_scan_history   = {}
brute_force_history = {}
syn_flood_history   = {}
os_fp_history       = {}
arp_table           = {}
ping_flood_history  = {}
http_flood_history  = {}
web_attack_history  = {}

TRUSTED_IPS  = ["127.0.0.1", "172.20.0.2", "172.20.0.1", "172.19.0.1"]
INTERNAL_IPS = ["127.0.0.1", "172.20.0.2", "172.20.0.1", "172.19.0.1"]

# Ports sensibles pour le brute force
# 80/443/8080 sont retirés : le brute force HTTP est détecté
# différemment (via connexions SYN répétées, pas les PA)
SENSITIVE_PORTS = {
    22:   "SSH",
    21:   "FTP",
    23:   "Telnet",
    3306: "MySQL",
    3389: "RDP",
    5900: "VNC",
}

# Ports HTTP : brute force détecté via SYN uniquement (connexions séparées)
HTTP_PORTS = {80: "HTTP", 443: "HTTPS", 8080: "HTTP-Alt"}


class Analyser:

    def _broadcast(self, alert_model):
        try:
            data = alert_model.model_dump()
            data["detection_time"] = str(data.get("detection_time", ""))
            data["_id"]            = str(data.get("id", ""))
            broadcast("alerts", data)
        except Exception as e:
            print(f"[!] Broadcast alert error: {e}")

    @staticmethod
    def _write_evidence(fileName, evidence):
        path = f"storage/captures/{fileName}"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'a') as f:
            try:
                f.write(evidence)
            except Exception as e:
                print(f"Erreur ecriture : {e}")

    # PORT SCAN
    def detect_port_scan(self, ip_src, port_dst, ip_dst, flags, iface):
        now = time.time()

        if ip_src in INTERNAL_IPS or ip_dst in INTERNAL_IPS:
            return False
        if str(flags).strip() != "S":
            return False

        if ip_src not in port_scan_history:
            port_scan_history[ip_src] = {"port": {port_dst}, "first_seen": now}
        else:
            port_scan_history[ip_src]["port"].add(port_dst)
            duration           = now - port_scan_history[ip_src]["first_seen"]
            unique_ports_count = len(port_scan_history[ip_src]["port"])

            if unique_ports_count > 10 and duration < 5:
                print(f"\n[!!!] DETECTION IDS : Port Scan par {ip_src}\n"
                      f"[i] Preuve : {unique_ports_count} ports en {duration:.2f}s")

                alert = AlertPortScan(
                    detection_time = dt.get_format_now(),
                    ip_src         = ip_src,
                    ip_dst         = ip_dst,
                    iface          = iface,
                    ports_scanned  = list(port_scan_history[ip_src]["port"]),
                    unique_ports   = unique_ports_count,
                    duration       = round(duration, 3)
                )
                Repository.save_port_scan_alert(alert)
                self._broadcast(alert)
                port_scan_history[ip_src] = {"port": set(), "first_seen": now}
                return True

            if duration >= 5:
                port_scan_history[ip_src] = {"port": {port_dst}, "first_seen": now}

        return False

    # BRUTE FORCE
    # Logique : on compte les SYN (nouvelles connexions) vers les ports sensibles
    # non-HTTP. Pour le HTTP, les PA sont des données dans une session existante,
    # pas des tentatives d'authentification séparées.
    # Pour SSH/FTP/RDP etc. : chaque SYN = une nouvelle tentative de connexion.
    # Pour HTTP basic auth : on détecte via les PA mais seulement si le payload
    # contient un header Authorization (voir branche HTTP ci-dessous).
    def detect_brute_force(self, ip_src, port_dst, ip_dst, flags, iface):
        now       = time.time()
        flags_str = str(flags).strip()

        if ip_src in INTERNAL_IPS or ip_dst in INTERNAL_IPS:
            return False

        # --- Ports non-HTTP (SSH, FTP, RDP...) : compter les SYN ---
        if port_dst in SENSITIVE_PORTS:
            # On compte uniquement les SYN : chaque SYN = nouvelle tentative
            if flags_str != "S":
                return False

            service = SENSITIVE_PORTS[port_dst]
            key     = f"bf:{ip_src}:{port_dst}"

            if key not in brute_force_history:
                brute_force_history[key] = {"count": 1, "first_seen": now}
                return False

            brute_force_history[key]["count"] += 1
            duration = now - brute_force_history[key]["first_seen"]
            count    = brute_force_history[key]["count"]

            if duration > 10:
                brute_force_history[key] = {"count": 1, "first_seen": now}
                return False

            if count > 8 and duration <= 10:
                print(f"\n[!!!] DETECTION IDS : Brute Force {service} par {ip_src}\n"
                      f"[i] Preuve : {count} connexions SYN sur port {port_dst} en {duration:.2f}s")

                alert = AlertBruteForce(
                    detection_time = dt.get_format_now(),
                    ip_src         = ip_src,
                    ip_dst         = ip_dst,
                    iface          = iface,
                    port_dst       = port_dst,
                    service        = service,
                    attempts       = count
                )
                Repository.save_brute_force_alert(alert)
                self._broadcast(alert)
                brute_force_history[key] = {"count": 0, "first_seen": now}
                return True

        return False

    # BRUTE FORCE HTTP (Basic Auth)
    # Appelé depuis le sniffer uniquement quand on a un payload HTTP brut
    # et qu'il contient un header Authorization.
    def detect_http_brute_force(self, ip_src, port_dst, ip_dst, iface, raw_payload):
        now = time.time()

        if ip_src in INTERNAL_IPS or ip_dst in INTERNAL_IPS:
            return False
        if port_dst not in HTTP_PORTS:
            return False

        # Vérifie la présence d'un header Authorization dans le payload
        try:
            payload_str = raw_payload.decode(errors="replace").lower()
            if "authorization:" not in payload_str:
                return False
        except Exception:
            return False

        service = HTTP_PORTS[port_dst]
        key     = f"bf_http:{ip_src}:{port_dst}"

        if key not in brute_force_history:
            brute_force_history[key] = {"count": 1, "first_seen": now}
            return False

        brute_force_history[key]["count"] += 1
        duration = now - brute_force_history[key]["first_seen"]
        count    = brute_force_history[key]["count"]

        if duration > 10:
            brute_force_history[key] = {"count": 1, "first_seen": now}
            return False

        if count > 8 and duration <= 10:
            print(f"\n[!!!] DETECTION IDS : Brute Force HTTP Basic Auth par {ip_src}\n"
                  f"[i] Preuve : {count} tentatives avec Authorization sur port {port_dst} en {duration:.2f}s")

            alert = AlertBruteForce(
                detection_time = dt.get_format_now(),
                ip_src         = ip_src,
                ip_dst         = ip_dst,
                iface          = iface,
                port_dst       = port_dst,
                service        = f"{service} Basic Auth",
                attempts       = count
            )
            Repository.save_brute_force_alert(alert)
            self._broadcast(alert)
            brute_force_history[key] = {"count": 0, "first_seen": now}
            return True

        return False

    # SYN FLOOD
    def detect_syn_flood(self, ip_src, port_dst, ip_dst, flags, iface):
        now = time.time()

        MAX_SYN_COUNT = 100
        MAX_DURATION  = 5

        if ip_src in INTERNAL_IPS or ip_dst in INTERNAL_IPS:
            return False
        if str(flags).strip() != "S":
            return False

        if ip_src not in syn_flood_history:
            syn_flood_history[ip_src] = {"count": 1, "first_seen": now, "ports": {port_dst}}
        else:
            syn_flood_history[ip_src]["count"] += 1
            syn_flood_history[ip_src]["ports"].add(port_dst)

        duration     = now - syn_flood_history[ip_src]["first_seen"]
        count        = syn_flood_history[ip_src]["count"]
        unique_ports = len(syn_flood_history[ip_src]["ports"])

        if unique_ports > 20:
            syn_flood_history[ip_src] = {"count": 1, "first_seen": now, "ports": {port_dst}}
            return False

        if duration > MAX_DURATION:
            syn_flood_history[ip_src] = {"count": 1, "first_seen": now, "ports": {port_dst}}
            return False

        if count > MAX_SYN_COUNT and duration <= MAX_DURATION:
            print(f"\n[!!!] DETECTION IDS : SYN Flood sur port {port_dst} par {ip_src}\n"
                  f"[i] Preuve : {count} paquets SYN en {duration:.2f}s")

            alert = AlertSynFlood(
                detection_time = dt.get_format_now(),
                ip_src         = ip_src,
                ip_dst         = ip_dst,
                iface          = iface,
                port_dst       = port_dst,
                syn_packets    = count,
                duration       = round(duration, 3)
            )
            Repository.save_syn_flood_alert(alert)
            self._broadcast(alert)
            self._write_evidence("evidence-syn-flood.txt",
                f"========== CAPTURE SYN FLOOD ==========\n"
                f"Source : {ip_src}\n"
                f"Victime : {ip_dst}:{port_dst}\n"
                f"Paquets SYN : {count} en {duration:.2f}s\n"
                f"========================================\n\n"
            )
            syn_flood_history[ip_src] = {"count": 0, "first_seen": now, "ports": set()}
            return True

        return False

    # OS FINGERPRINTING
    def detect_os_fingerprinting(self, ip_src, port_dst, ip_dst, flags, iface):
        now = time.time()

        if ip_src in INTERNAL_IPS or ip_dst in INTERNAL_IPS:
            return False
        if flags is None:
            return False

        ABNORMAL_FLAGS = {
            "":    "NULL scan",
            "F":   "FIN scan",
            "FPU": "XMAS scan",
            "FA":  "Maimon scan",
            "SE":  "ECN scan",
            "FU":  "FIN+URG",
            "PU":  "PSH+URG",
        }

        flags_str    = str(flags).strip()
        matched_type = ABNORMAL_FLAGS.get(flags_str)
        if matched_type is None:
            return False

        key = f"fingerprinting:{ip_src}"

        if key not in os_fp_history:
            os_fp_history[key] = {"count": 1, "first_seen": now, "types": [matched_type]}
        else:
            os_fp_history[key]["count"] += 1
            os_fp_history[key]["types"].append(matched_type)
            count    = os_fp_history[key]["count"]
            duration = now - os_fp_history[key]["first_seen"]

            if duration > 10:
                os_fp_history[key] = {"count": 1, "first_seen": now, "types": [matched_type]}
                return False

            if count >= 3 and duration <= 10:
                types_uniques = list(set(os_fp_history[key]["types"]))
                print(f"\n[!!!] DETECTION IDS : OS Fingerprinting par {ip_src}\n"
                      f"[i] Preuve : {count} paquets en {duration:.2f}s\n"
                      f"[i] Types  : {', '.join(types_uniques)}")

                alert = AlertOsFingerprinting(
                    detection_time = dt.get_format_now(),
                    ip_src         = ip_src,
                    ip_dst         = ip_dst,
                    iface          = iface,
                    port_dst       = port_dst,
                    packets_count  = count,
                    duration       = round(duration, 3),
                    scan_types     = types_uniques
                )
                Repository.save_os_fingerprinting_alert(alert)
                self._broadcast(alert)
                os_fp_history[key] = {"count": 0, "first_seen": now, "types": []}
                return True

        return False

    # ARP SPOOFING
    def detect_arp_spoofing(self, ip_src, ip_dst, mac_src, iface):
        now = time.time()

        if ip_src in INTERNAL_IPS or ip_dst in INTERNAL_IPS:
            return False
        if ip_src.startswith("224.") or ip_src in ("255.255.255.255", "0.0.0.0"):
            return False

        if ip_src not in arp_table:
            arp_table[ip_src] = {"mac": mac_src, "first_seen": now}
            return False

        known_mac = arp_table[ip_src]["mac"]

        if known_mac != mac_src:
            print(f"\n[!!!] DETECTION IDS : ARP Spoofing détecté !\n"
                  f"[i] IP usurpée : {ip_src}\n"
                  f"[i] MAC légitime : {known_mac}\n"
                  f"[i] MAC frauduleux : {mac_src}")

            alert = AlertArpSpoofing(
                detection_time = dt.get_format_now(),
                ip_src         = ip_src,
                ip_dst         = ip_dst,
                iface          = iface,
                ip_spoofed     = ip_src,
                mac_legitimate = known_mac,
                mac_fraudulent = mac_src,
                target_ip      = ip_dst
            )
            Repository.save_arp_spoofing_alert(alert)
            self._broadcast(alert)
            self._write_evidence("evidence-arp-spoofing.txt",
                f"========== CAPTURE ARP SPOOFING ==========\n"
                f"IP usurpée : {ip_src}\n"
                f"MAC légitime : {known_mac}\n"
                f"MAC frauduleux : {mac_src}\n"
                f"==========================================\n\n"
            )
            arp_table[ip_src] = {"mac": mac_src, "first_seen": now}
            return True

        return False

    # PING FLOOD (ICMP FLOOD)
    def detect_ping_flood(self, ip_src, ip_dst, code, icmp_type, iface):
        now = time.time()

        MAX_ICMP_COUNT = 100
        MAX_DURATION   = 5

        if ip_src in INTERNAL_IPS or ip_dst in INTERNAL_IPS:
            return False
        if icmp_type != 8 or code != 0:
            return False

        if ip_src not in ping_flood_history:
            ping_flood_history[ip_src] = {"count": 1, "first_seen": now}
        else:
            ping_flood_history[ip_src]["count"] += 1

        duration = now - ping_flood_history[ip_src]["first_seen"]
        count    = ping_flood_history[ip_src]["count"]

        if duration > MAX_DURATION:
            ping_flood_history[ip_src] = {"count": 1, "first_seen": now}
            return False

        if count > MAX_ICMP_COUNT and duration <= MAX_DURATION:
            print(f"\n[!!!] DETECTION IDS : Ping Flood par {ip_src}\n"
                  f"[i] Preuve : {count} paquets ICMP en {duration:.2f}s")

            alert = AlertPingFlood(
                detection_time = dt.get_format_now(),
                ip_src         = ip_src,
                ip_dst         = ip_dst,
                iface          = iface,
                icmp_packets   = count,
                duration       = round(duration, 3)
            )
            Repository.save_ping_flood_alert(alert)
            self._broadcast(alert)
            self._write_evidence("evidence-ping-flood.txt",
                f"========== CAPTURE PING FLOOD ==========\n"
                f"Source : {ip_src}\n"
                f"Victime : {ip_dst}\n"
                f"Paquets ICMP : {count} en {duration:.2f}s\n"
                f"=========================================\n\n"
            )
            ping_flood_history[ip_src] = {"count": 0, "first_seen": now}
            return True

        return False

    # HTTP FLOOD
    # Appelé uniquement depuis le bloc HTTP du sniffer (payload brut détecté)
    def detect_http_flood(self, ip_src, port_dst, ip_dst, iface):
        now = time.time()

        MAX_HTTP_REQUESTS = 50
        MAX_DURATION      = 5

        if ip_src in INTERNAL_IPS or ip_dst in INTERNAL_IPS:
            return False
        if port_dst not in HTTP_PORTS:
            return False

        key = f"httpflood:{ip_src}:{port_dst}"

        if key not in http_flood_history:
            http_flood_history[key] = {"count": 1, "first_seen": now}
            return False

        http_flood_history[key]["count"] += 1
        duration = now - http_flood_history[key]["first_seen"]
        count    = http_flood_history[key]["count"]

        if duration > MAX_DURATION:
            http_flood_history[key] = {"count": 1, "first_seen": now}
            return False

        if count > MAX_HTTP_REQUESTS and duration <= MAX_DURATION:
            print(f"\n[!!!] DETECTION IDS : HTTP Flood par {ip_src}\n"
                  f"[i] Preuve : {count} requêtes HTTP en {duration:.2f}s sur port {port_dst}")

            alert = AlertHttpFlood(
                detection_time = dt.get_format_now(),
                ip_src         = ip_src,
                ip_dst         = ip_dst,
                iface          = iface,
                port_dst       = port_dst,
                http_requests  = count,
                duration       = round(duration, 3)
            )
            Repository.save_http_flood_alert(alert)
            self._broadcast(alert)
            self._write_evidence("evidence-http-flood.txt",
                f"========== CAPTURE HTTP FLOOD ==========\n"
                f"Source : {ip_src}\n"
                f"Victime : {ip_dst}:{port_dst}\n"
                f"Requêtes HTTP : {count} en {duration:.2f}s\n"
                f"=========================================\n\n"
            )
            http_flood_history[key] = {"count": 0, "first_seen": now}
            return True

        return False

    # DÉTECTION SQLi / XSS — niveau applicatif (HTTP)
    def detect_web_attack(self, ip_src, ip_dst, http_path, iface):
        if not LIBINJECTION_AVAILABLE:
            return False
        if ip_src in INTERNAL_IPS or ip_dst in INTERNAL_IPS:
            return False
        if not http_path:
            return False

        try:
            decoded_path = http_path.decode() if isinstance(http_path, bytes) else http_path
        except Exception:
            return False

        detected_type = None

        if is_sql_injection(decoded_path):
            detected_type = "SQL_INJECTION"
        elif is_xss(decoded_path):
            detected_type = "XSS"

        if detected_type is None:
            return False

        print(f"\n[!!!] DETECTION IDS : {detected_type} par {ip_src}\n"
              f"[i] Payload suspect : {decoded_path}")

        alert = AlertWebAttack(
            detection_time  = dt.get_format_now(),
            ip_src          = ip_src,
            ip_dst          = ip_dst,
            iface           = iface,
            port_dst        = 80,
            web_attack_type = detected_type,
            payload         = decoded_path[:500],
        )
        Repository.save_web_attack_alert(alert)
        self._broadcast(alert)
        self._write_evidence(f"evidence-{detected_type.lower()}.txt",
            f"========== CAPTURE {detected_type} ==========\n"
            f"Source  : {ip_src}\n"
            f"Victime : {ip_dst}\n"
            f"Payload : {decoded_path}\n"
            f"================================================\n\n"
        )
        return True