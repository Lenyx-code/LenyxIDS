from utils.datetime_utils import DatetimeUtils as dt
import time
import os

port_scan_history  = {}
brute_force_history = {}
syn_flood_history  = {}
os_fp_history      = {}
arp_table          = {}
port_scanned       = []

active_attacks = {}   # { "ip": {"type": "syn_flood", "since": timestamp} }

TRUSTED_IPS = ["127.0.0.1"]

class Analyser:

    @staticmethod
    def _write_evidence_to_file(fileName, evidence):
        path = f"storage/captures/{fileName}"
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'a') as f:
            try:
                f.write(evidence)
            except Exception as e:
                print(f"Erreur d'ecriture : {e}")

    def _set_active_attack(self, ip_src, attack_type, duration=30):
        """Enregistre une attaque active pour bloquer les faux positifs"""
        active_attacks[ip_src] = {
            "type": attack_type,
            "since": time.time(),
            "duration": duration
        }

    def _is_attack_active(self, ip_src, attack_type):
        """Vérifie si une attaque d'un certain type est déjà active pour cette IP"""
        if ip_src not in active_attacks:
            return False
        entry = active_attacks[ip_src]
        elapsed = time.time() - entry["since"]

        if elapsed > entry["duration"]:
            del active_attacks[ip_src]
            return False
        return entry["type"] == attack_type

    def _any_attack_active(self, ip_src):
        """Vérifie si N'IMPORTE QUELLE attaque est active pour cette IP"""
        if ip_src not in active_attacks:
            return False
        entry = active_attacks[ip_src]
        if time.time() - entry["since"] > entry["duration"]:
            del active_attacks[ip_src]
            return False
        return True

    def detect_port_scan(self, ip_src, port_dst, ip_dst, flags):
        global port_scan_history
        now = time.time()
        detection_datetime = dt.get_format_now()

        if ip_src in TRUSTED_IPS:
            return False

        if self._is_attack_active(ip_src, "syn_flood"):
            return False

        if str(flags).strip() != "S":
            return False

        if ip_src not in port_scan_history:
            port_scan_history[ip_src] = {"port": {port_dst}, "first_seen": now}
        else:
            port_scan_history[ip_src]["port"].add(port_dst)
            duration = now - port_scan_history[ip_src]["first_seen"]
            unique_ports_count = len(port_scan_history[ip_src]["port"])
            port_scanned.append(port_dst)

            if unique_ports_count > 10 and duration < 5:
                msg = (
                    f"\n[!!!] DETECTION IDS : Port Scan par {ip_src}\n"
                    f"[i] Preuve : {unique_ports_count} ports scannés en {duration:.2f}s\n"
                )
                print(msg)
                evidence = (
                    f"========== CAPTURES SCAN DE PORTS ==========\n"
                    f"[!!!] Alerte générée à : {detection_datetime}\n"
                    f"Source suspecte : {ip_src}\n"
                    f"Victime : {ip_dst}\n"
                    f"Ports ciblés : {port_scanned}\n"
                    f"Statistiques : {unique_ports_count} ports en {duration:.2f}s\n"
                    f"=============================================\n\n"
                )
                self._write_evidence_to_file("evidence-port-scan.txt", evidence)
                self._set_active_attack(ip_src, "port_scan", duration=20)
                port_scan_history[ip_src] = {"port": set(), "first_seen": now}
                return True

        return False

    def detect_brute_force(self, ip_src, port_dst, ip_dst, flags):
        now = time.time()
        detection_datetime = dt.get_format_now()
        flags_str = str(flags).strip()

        if ip_src in TRUSTED_IPS:
            return False

        if self._is_attack_active(ip_src, "syn_flood"):
            return False
        if self._is_attack_active(ip_src, "port_scan"):
            return False

        SENSITIVE_PORTS = {
            22: "SSH", 21: "FTP", 23: "Telnet",
            80: "HTTP", 443: "HTTPS", 3306: "MySQL",
            3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
        }

        BRUTE_FORCE_FLAGS = {"PA", "A"}
        if port_dst not in SENSITIVE_PORTS:
            return False
        if flags_str not in BRUTE_FORCE_FLAGS:
            return False

        service = SENSITIVE_PORTS[port_dst]
        key = f"{ip_src}:{port_dst}"

        if key not in brute_force_history:
            brute_force_history[key] = {"count": 1, "first_seen": now}
        else:
            brute_force_history[key]["count"] += 1
            duration = now - brute_force_history[key]["first_seen"]
            count = brute_force_history[key]["count"]

            if duration > 10 and count <= 8:
                brute_force_history[key] = {"count": 1, "first_seen": now}
                return False

            if count > 8 and duration < 10:
                msg = (
                    f"\n[!!!] DETECTION IDS : Brute Force {service} par {ip_src}\n"
                    f"[i] Preuve : {count} tentatives sur port {port_dst} en {duration:.2f}s\n"
                )
                print(msg)
                evidence = (
                    f"========== CAPTURE BRUTE FORCE ==========\n"
                    f"Alerte générée à   : {detection_datetime}\n"
                    f"Type               : Brute Force {service}\n"
                    f"Source suspecte    : {ip_src}\n"
                    f"Victime            : {ip_dst}:{port_dst}\n"
                    f"Tentatives         : {count} en {duration:.2f}s\n"
                    f"=========================================\n\n"
                )
                self._write_evidence_to_file("evidence-brute-force.txt", evidence)
                self._set_active_attack(ip_src, "brute_force", duration=20)
                brute_force_history[key] = {"count": 0, "first_seen": now}
                return True

        return False

    def detect_syn_flood(self, ip_src, port_dst, ip_dst, flags):
        global syn_flood_history
        now = time.time()

        MAX_SYN_COUNT = 100
        MAX_DURATION  = 5

        if ip_src in TRUSTED_IPS:
            return False

        if str(flags).strip() != "S":
            return False

        if ip_src not in syn_flood_history:
            syn_flood_history[ip_src] = {"count": 1, "first_seen": now}
        else:
            syn_flood_history[ip_src]["count"] += 1

        duration = now - syn_flood_history[ip_src]["first_seen"]
        count    = syn_flood_history[ip_src]["count"]

        if duration > MAX_DURATION and count <= MAX_SYN_COUNT:
            syn_flood_history[ip_src] = {"count": 1, "first_seen": now}
            return False

        if count > MAX_SYN_COUNT and duration <= MAX_DURATION:
            msg = (
                f"\n[!!!] DETECTION IDS : SYN Flood sur port {port_dst} par {ip_src}\n"
                f"[i] Preuve : {count} paquets SYN en {duration:.2f}s\n"
            )
            print(msg)
            detection_datetime = dt.get_format_now()
            evidence = (
                f"========== CAPTURE SYN FLOOD ==========\n"
                f"Alerte générée à   : {detection_datetime}\n"
                f"Source suspecte    : {ip_src}\n"
                f"Victime            : {ip_dst}:{port_dst}\n"
                f"Paquets SYN        : {count} en {duration:.2f}s\n"
                f"=======================================\n\n"
            )
            self._write_evidence_to_file("evidence-syn-flood.txt", evidence)

            self._set_active_attack(ip_src, "syn_flood", duration=30)
            syn_flood_history[ip_src] = {"count": 0, "first_seen": now}
            return True

        return False

    def detect_os_fingerprinting(self, ip_src, port_dst, ip_dst, flags):
        global os_fp_history
        now = time.time()

        if ip_src in TRUSTED_IPS:
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

        flags_str = str(flags).strip()
        matched_type = ABNORMAL_FLAGS.get(flags_str)

        if matched_type is None:
            return False

        detection_datetime = dt.get_format_now()
        key = f"fingerprinting:{ip_src}"

        if key not in os_fp_history:
            os_fp_history[key] = {"count": 1, "first_seen": now, "types": [matched_type]}
        else:
            os_fp_history[key]["count"] += 1
            os_fp_history[key]["types"].append(matched_type)
            count    = os_fp_history[key]["count"]
            duration = now - os_fp_history[key]["first_seen"]

            if duration > 10 and count < 3:
                os_fp_history[key] = {"count": 1, "first_seen": now, "types": [matched_type]}
                return False

            if count >= 3 and duration < 10:
                types_uniques = list(set(os_fp_history[key]["types"]))
                msg = (
                    f"\n[!!!] DETECTION IDS : OS Fingerprinting par {ip_src}\n"
                    f"[i] Preuve : {count} paquets suspects en {duration:.2f}s\n"
                    f"[i] Types  : {', '.join(types_uniques)}\n"
                )
                print(msg)
                evidence = (
                    f"========== CAPTURE OS FINGERPRINTING ==========\n"
                    f"Alerte générée à   : {detection_datetime}\n"
                    f"Source suspecte    : {ip_src}\n"
                    f"Victime            : {ip_dst}:{port_dst}\n"
                    f"Paquets suspects   : {count} en {duration:.2f}s\n"
                    f"Types détectés     : {', '.join(types_uniques)}\n"
                    f"================================================\n\n"
                )
                self._write_evidence_to_file("evidence-fingerprint.txt", evidence)
                self._set_active_attack(ip_src, "os_fingerprint", duration=20)
                os_fp_history[key] = {"count": 0, "first_seen": now, "types": []}
                return True

        return False

    def detect_arp_spoofing(self, ip_src, ip_dst, mac_src):
        global arp_table
        now = time.time()
        detection_datetime = dt.get_format_now()

        if ip_src in TRUSTED_IPS:
            return False

        if ip_src.startswith("224.") or ip_src == "255.255.255.255" or ip_src == "0.0.0.0":
            return False

        if ip_src not in arp_table:
            arp_table[ip_src] = {"mac": mac_src, "first_seen": now}
            return False

        known_mac = arp_table[ip_src]["mac"]

        if known_mac != mac_src:
            msg = (
                f"\n[!!!] DETECTION IDS : ARP Spoofing détecté !\n"
                f"[i] IP usurpée     : {ip_src}\n"
                f"[i] MAC légitime   : {known_mac}\n"
                f"[i] MAC frauduleux : {mac_src}\n"
                f"[i] Cible          : {ip_dst}\n"
            )
            print(msg)
            evidence = (
                f"========== CAPTURE ARP SPOOFING ==========\n"
                f"Alerte générée à   : {detection_datetime}\n"
                f"IP usurpée         : {ip_src}\n"
                f"MAC légitime       : {known_mac}\n"
                f"MAC frauduleux     : {mac_src}\n"
                f"Cible attaquée     : {ip_dst}\n"
                f"==========================================\n\n"
            )
            self._write_evidence_to_file("evidence-arp-spoofing.txt", evidence)
            arp_table[ip_src] = {"mac": mac_src, "first_seen": now}
            return True

        return False