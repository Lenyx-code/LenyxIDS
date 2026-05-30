from database.mongodb.connection import Connection as c
from database.mongodb.models.packet import Packet
from database.mongodb.models.alert import *
from database.mongodb.models.forensic_report import ForensicReport
from datetime import datetime
from bson import ObjectId
import hashlib
import json


class Repository:


    @staticmethod
    def _compute_hash(data: dict) -> str:
        """Hash SHA-256 du contenu pour garantir l'intégrité de la preuve"""
        exclude = {"integrity_hash", "_id"}
        clean   = {k: v for k, v in data.items() if k not in exclude}
        content = json.dumps(clean, sort_keys=True, default=str)
        return hashlib.sha256(content.encode()).hexdigest()

    @staticmethod
    def verify_integrity(document: dict) -> bool:
        """Vérifie qu'une alerte n'a pas été modifiée depuis son insertion"""
        stored_hash = document.get("integrity_hash")
        if not stored_hash:
            return False
        exclude = {"integrity_hash", "_id"}
        clean   = {k: v for k, v in document.items() if k not in exclude}
        content = json.dumps(clean, sort_keys=True, default=str)
        computed = hashlib.sha256(content.encode()).hexdigest()
        return stored_hash == computed

    @staticmethod
    def _prepare_alert(alert_model) -> dict:
        """Convertit le modèle Pydantic en dict + ajoute le hash d'intégrité"""
        data = alert_model.model_dump(by_alias=True, exclude_none=True)
        data["integrity_hash"] = Repository._compute_hash(data)
        return data


    @staticmethod
    def save_packets_batch(packets: list[dict]):
        if not packets:
            return
        con    = c.get_mongodb_connection("packets")
        result = con.insert_many(packets)
        print(f"MONGODB: save_packets_batch > {len(result.inserted_ids)} paquets")
        return result.inserted_ids

    @staticmethod
    def get_packets_after(last_id=None, limit=50) -> list:
        con   = c.get_mongodb_connection("packets")
        query = {"_id": {"$gt": ObjectId(last_id)}} if last_id else {}
        return list(con.find(query).sort("timestamp", 1).limit(limit))

    @staticmethod
    def count_packets_by_ip(attacker_ip: str) -> int:
        con = c.get_mongodb_connection("packets")
        return con.count_documents({"ip_src": attacker_ip})


    @staticmethod
    def _save_alert(alert_model) -> str:
        """Méthode générique — évite la duplication de code"""
        con    = c.get_mongodb_connection("alerts")
        data   = Repository._prepare_alert(alert_model)
        result = con.insert_one(data)
        return str(result.inserted_id)

    @staticmethod
    def save_port_scan_alert(alert: AlertPortScan) -> str:
        inserted_id = Repository._save_alert(alert)
        print(f"MONGODB: save_port_scan_alert > {inserted_id}")
        return inserted_id

    @staticmethod
    def save_brute_force_alert(alert: AlertBruteForce) -> str:
        inserted_id = Repository._save_alert(alert)
        print(f"MONGODB: save_brute_force_alert > {inserted_id}")
        return inserted_id

    @staticmethod
    def save_syn_flood_alert(alert: AlertSynFlood) -> str:
        inserted_id = Repository._save_alert(alert)
        print(f"MONGODB: save_syn_flood_alert > {inserted_id}")
        return inserted_id

    @staticmethod
    def save_os_fingerprinting_alert(alert: AlertOsFingerprinting) -> str:
        inserted_id = Repository._save_alert(alert)
        print(f"MONGODB: save_os_fingerprinting_alert > {inserted_id}")
        return inserted_id

    @staticmethod
    def save_arp_spoofing_alert(alert: AlertArpSpoofing) -> str:
        inserted_id = Repository._save_alert(alert)
        print(f"MONGODB: save_arp_spoofing_alert > {inserted_id}")
        return inserted_id

    @staticmethod
    def get_alerts_by_ip(attacker_ip: str) -> list:
        con = c.get_mongodb_connection("alerts")
        return list(con.find({"ip_src": attacker_ip}).sort("detection_time", 1))

    @staticmethod
    def get_all_alerts(limit=100) -> list:
        con = c.get_mongodb_connection("alerts")
        return list(con.find().sort("detection_time", -1).limit(limit))

    @staticmethod
    def get_alerts_after(last_id=None, limit=20) -> list:
        """Pour le stream SSE des alertes en temps réel"""
        con   = c.get_mongodb_connection("alerts")
        query = {"_id": {"$gt": ObjectId(last_id)}} if last_id else {}
        return list(con.find(query).sort("detection_time", -1).limit(limit))

    @staticmethod
    def save_report(report: ForensicReport) -> str:
        con  = c.get_mongodb_connection("forensic_reports")
        data = report.model_dump(by_alias=True, exclude_none=True)
        data["integrity_hash"] = Repository._compute_hash(data)
        result = con.insert_one(data)
        print(f"MONGODB: save_report > {result.inserted_id}")
        return str(result.inserted_id)

    @staticmethod
    def count_reports_today() -> int:
        con   = c.get_mongodb_connection("forensic_reports")
        today = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
        return con.count_documents({"generated_at": {"$gte": today}})

    @staticmethod
    def get_all_reports() -> list:
        con = c.get_mongodb_connection("forensic_reports")
        return list(con.find().sort("generated_at", -1))

    @staticmethod
    def get_report_by_id(report_id: str) -> dict:
        con = c.get_mongodb_connection("forensic_reports")
        return con.find_one({"_id": ObjectId(report_id)})


    @staticmethod
    def save_pcap_hash(data: dict) -> str:
        con    = c.get_mongodb_connection("pcap_hashes")
        result = con.insert_one(data)
        print(f"MONGODB: save_pcap_hash > {result.inserted_id}")
        return str(result.inserted_id)