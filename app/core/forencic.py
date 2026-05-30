from datetime import datetime
from database.mongodb.models.forensic_report import ForensicReport, AttackEvent
from database.mongodb.repository import Repository
from scapy.all import PcapWriter
from scapy.layers.inet import IP, TCP, UDP
import threading
import hashlib
import atexit
import signal
import os


class Forensic:

    _packet_buffer     = []
    _buffer_lock       = threading.Lock()
    _flush_interval    = 2
    _pcap_writer       = None
    _pcap_lock         = threading.Lock()
    _current_pcap_file = None
    _pcap_initialized  = False

    @classmethod
    def init_pcap_file(cls):
        """Ouvre le fichier PCAP + enregistre la fermeture automatique"""
        if cls._pcap_initialized:
            return cls._current_pcap_file

        path = "storage/pcap/"
        os.makedirs(path, exist_ok=True)
        fileName = f"{path}capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap"

        cls._pcap_writer       = PcapWriter(fileName, append=False, sync=True)
        cls._current_pcap_file = fileName
        cls._pcap_initialized  = True
        atexit.register(cls._shutdown)
        signal.signal(signal.SIGINT,  lambda s, f: cls._shutdown())
        signal.signal(signal.SIGTERM, lambda s, f: cls._shutdown())

        print(f"[*] PCAP ouvert : {fileName}")
        return fileName

    @classmethod
    def write_pcap(cls, packet):
        with cls._pcap_lock:
            if cls._pcap_writer:
                cls._pcap_writer.write(packet)

    @classmethod
    def close_pcap(cls):
        """Ferme le PCAP, calcule et sauvegarde son hash SHA-256"""
        with cls._pcap_lock:
            if not cls._pcap_writer:
                return
            cls._pcap_writer.flush()
            cls._pcap_writer.close()
            cls._pcap_writer     = None
            cls._pcap_initialized = False

            print(f"[*] PCAP fermé : {cls._current_pcap_file}")
            try:
                with open(cls._current_pcap_file, "rb") as f:
                    pcap_hash = hashlib.sha256(f.read()).hexdigest()

                Repository.save_pcap_hash({
                    "file":       cls._current_pcap_file,
                    "sha256":     pcap_hash,
                    "created_at": datetime.utcnow()
                })
                print(f"[*] PCAP hash sauvegardé : {pcap_hash[:16]}...")

            except Exception as e:
                print(f"[!] Erreur hash PCAP : {e}")

    @classmethod
    def _shutdown(cls):
        """Arrêt propre — flush buffer + fermeture PCAP"""
        print("\n[*] Arrêt détecté — sauvegarde en cours...")
        cls._flush_buffer()
        cls.close_pcap()
        print("[*] Arrêt propre terminé")
        os._exit(0)

    @classmethod
    def start_buffer_flusher(cls):
        """Lance le thread qui flush le buffer vers MongoDB toutes les 2s"""
        def flusher():
            import time
            while True:
                time.sleep(cls._flush_interval)
                cls._flush_buffer()

        threading.Thread(target=flusher, daemon=True, name="BufferFlusher").start()
        print("[*] Buffer flusher démarré")

    @classmethod
    def _flush_buffer(cls):
        """Envoie tous les paquets du buffer vers MongoDB en une seule requête"""
        with cls._buffer_lock:
            if not cls._packet_buffer:
                return
            batch = cls._packet_buffer.copy()
            cls._packet_buffer.clear()
        try:
            Repository.save_packets_batch(batch)
        except Exception as e:
            print(f"[-] Erreur flush buffer : {e}")

    @classmethod
    def save_captured_packet(cls, packet, iface_name: str, protocol_name: str):
        """Écrit dans le PCAP + ajoute au buffer MongoDB"""
        cls.write_pcap(packet)

        ip_src = ip_dst = "0.0.0.0"
        port_src = port_dst = None

        if packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            if packet.haslayer(TCP):
                port_src = packet[TCP].sport
                port_dst = packet[TCP].dport
            elif packet.haslayer(UDP):
                port_src = packet[UDP].sport
                port_dst = packet[UDP].dport

        with cls._buffer_lock:
            cls._packet_buffer.append({
                "timestamp": datetime.utcnow(),
                "protocol":  protocol_name,
                "ip_src":    ip_src,
                "ip_dst":    ip_dst,
                "port_src":  port_src,
                "port_dst":  port_dst,
                "iface":     iface_name,
                "pcap_file": cls._current_pcap_file
            })

    @classmethod
    def generate_report(cls, attacker_ip: str, victim_ip: str) -> ForensicReport | None:
        """Génère un rapport complet à partir des alertes MongoDB"""
        alerts = Repository.get_alerts_by_ip(attacker_ip)

        if not alerts:
            print(f"[!] Aucune alerte pour : {attacker_ip}")
            return None

        attack_types = set()
        timeline     = []

        for alert in alerts:
            attack_types.add(alert["attack_type"])
            timeline.append(AttackEvent(
                time        = alert["detection_time"],
                attack_type = alert["attack_type"],
                description = cls._describe(alert),
                ip_src      = alert["ip_src"],
                ip_dst      = alert["ip_dst"]
            ))

        timeline.sort(key=lambda e: e.time)

        report = ForensicReport(
            incident_id     = cls._generate_incident_id(),
            start_date      = timeline[0].time,
            end_date        = timeline[-1].time,
            attacker_ip     = attacker_ip,
            victim_ip       = victim_ip,
            title           = cls._generate_title(attack_types),
            severity        = cls._compute_severity(attack_types),
            attack_types    = list(attack_types),
            total_alerts    = len(alerts),
            timeline        = timeline,
            alerts_ids      = [str(a["_id"]) for a in alerts],
            pcap_file       = cls._current_pcap_file,
            conclusion      = cls._generate_conclusion(attack_types, attacker_ip, victim_ip),
            recommendations = cls._generate_recommendations(attack_types)
        )

        Repository.save_report(report)
        print(f"[*] Rapport généré : {report.incident_id}")
        return report


    @staticmethod
    def _generate_incident_id() -> str:
        date_str = datetime.now().strftime("%Y%m%d")
        count    = Repository.count_reports_today() + 1
        return f"INC-{date_str}-{count:03d}"

    @staticmethod
    def _describe(alert: dict) -> str:
        t = alert["attack_type"]
        if t == "PORT_SCAN":
            return f"Scan de {alert.get('unique_ports','?')} ports en {alert.get('duration','?')}s"
        if t == "BRUTE_FORCE":
            return f"Brute Force {alert.get('service','?')} — {alert.get('attempts','?')} tentatives"
        if t == "SYN_FLOOD":
            return f"SYN Flood — {alert.get('syn_packets','?')} paquets en {alert.get('duration','?')}s"
        if t == "OS_FINGERPRINTING":
            return f"OS Fingerprinting — {', '.join(alert.get('scan_types', []))}"
        if t == "ARP_SPOOFING":
            return f"ARP Spoofing — {alert.get('ip_spoofed','?')} usurpée"
        return "Activité suspecte"

    @staticmethod
    def _compute_severity(attack_types: set) -> str:
        if "SYN_FLOOD" in attack_types or "ARP_SPOOFING" in attack_types:
            return "CRITICAL"
        if "BRUTE_FORCE" in attack_types or "PORT_SCAN" in attack_types:
            return "HIGH"
        if "OS_FINGERPRINTING" in attack_types:
            return "MEDIUM"
        return "LOW"

    @staticmethod
    def _generate_title(attack_types: set) -> str:
        if len(attack_types) >= 3:
            return "Intrusion complète multi-vecteurs détectée"
        if "BRUTE_FORCE" in attack_types and "PORT_SCAN" in attack_types:
            return "Tentative d'intrusion — Scan + Brute Force"
        if "SYN_FLOOD" in attack_types:
            return "Attaque par déni de service détectée"
        if "ARP_SPOOFING" in attack_types:
            return "Attaque Man-in-the-Middle détectée"
        return "Activité malveillante détectée"

    @staticmethod
    def _generate_conclusion(attack_types: set, attacker_ip: str, victim_ip: str) -> str:
        attacks = ", ".join(attack_types)
        return (
            f"L'adresse IP {attacker_ip} a mené une attaque [{attacks}] "
            f"contre {victim_ip}. Les preuves collectées incluent les paquets "
            f"capturés (PCAP) et les alertes IDS enregistrées en base de données."
        )

    @staticmethod
    def _generate_recommendations(attack_types: set) -> list[str]:
        recs = ["Bloquer immédiatement l'IP source au pare-feu"]
        if "PORT_SCAN" in attack_types:
            recs.append("Fermer les ports inutiles et activer un pare-feu applicatif")
        if "BRUTE_FORCE" in attack_types:
            recs.append("Activer l'authentification à deux facteurs (2FA)")
            recs.append("Limiter les tentatives de connexion (fail2ban)")
        if "SYN_FLOOD" in attack_types:
            recs.append("Activer SYN cookies sur le serveur")
            recs.append("Mettre en place un rate limiting réseau")
        if "ARP_SPOOFING" in attack_types:
            recs.append("Activer le Dynamic ARP Inspection (DAI)")
            recs.append("Utiliser des entrées ARP statiques pour les équipements critiques")
        if "OS_FINGERPRINTING" in attack_types:
            recs.append("Désactiver les réponses ICMP inutiles")
            recs.append("Normaliser les réponses TCP pour masquer l'OS")
        return recs