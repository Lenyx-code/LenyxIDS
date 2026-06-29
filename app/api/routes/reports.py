from fastapi import APIRouter, Query
from database.mongodb.connection import Connection as c
from database.mongodb.repository import Repository
from core.forencic import Forensic
from bson import ObjectId
from datetime import datetime
import math

router = APIRouter()


def _serialize(docs: list) -> list:
    result = []
    for doc in docs:
        d = dict(doc)
        if "_id" in d:
            d["_id"] = str(d["_id"])
        for k, v in d.items():
            if isinstance(v, datetime):
                d[k] = v.isoformat()
            elif isinstance(v, list):
                d[k] = [
                    item.isoformat() if isinstance(item, datetime) else item
                    for item in v
                ]
        result.append(d)
    return result


# ─── Génération — AVANT /{report_id} pour éviter le conflit de route ──

@router.post("/reports/generate", tags=["Rapports"])
async def generate_report(body: dict):
    """
    Génère un rapport d'incident à partir des alertes existantes
    pour une paire attaquant/victime, et le sauvegarde en BD.
    """
    attacker_ip = body.get("attacker_ip")
    victim_ip   = body.get("victim_ip")

    if not attacker_ip or not victim_ip:
        return {"error": "attacker_ip et victim_ip sont requis"}

    report = Forensic.generate_report(attacker_ip, victim_ip)

    if report is None:
        return {"error": f"Aucune alerte trouvée pour l'IP {attacker_ip}"}

    return {"success": True, "data": report.model_dump()}


@router.get("/reports/attackers", tags=["Rapports"])
async def get_distinct_attackers():
    """
    Liste les IPs sources distinctes ayant des alertes —
    utile pour proposer un menu déroulant côté frontend
    avant de générer un rapport.
    """
    con = c.get_mongodb_connection("alerts")
    ips = con.distinct("ip_src")
    return {"data": ips}


# ─── Liste paginée ──────────────────────────────────────────────

@router.get("/reports", tags=["Rapports"])
async def get_all_reports(
    page:        int = Query(default=1, ge=1),
    limit:       int = Query(default=20, ge=1, le=100),
    severity:    str = Query(default=None),
    attacker_ip: str = Query(default=None),
    sort_order:  int = Query(default=-1),
):
    con   = c.get_mongodb_connection("forensic_reports")  # même collection que Repository.save_report
    query = {}

    if severity:
        query["severity"] = severity
    if attacker_ip:
        query["attacker_ip"] = {"$regex": attacker_ip, "$options": "i"}

    total   = con.count_documents(query)
    reports = list(
        con.find(query)
           .sort("generated_at", sort_order)
           .skip((page - 1) * limit)
           .limit(limit)
    )

    return {
        "data":        _serialize(reports),
        "total":       total,
        "page":        page,
        "limit":       limit,
        "total_pages": math.ceil(total / limit) if total > 0 else 1,
        "has_next":    page < math.ceil(total / limit) if total > 0 else False,
        "has_prev":    page > 1,
    }


# ─── Détail — EN DERNIER (route dynamique) ────────────────────

@router.get("/reports/{report_id}", tags=["Rapports"])
async def get_report_by_id(report_id: str):
    try:
        report = Repository.get_report_by_id(report_id)
        if not report:
            return {"error": "Rapport non trouvé"}

        is_valid = Repository.verify_integrity(dict(report))

        return {
            "data":            _serialize([report])[0],
            "integrity_valid": is_valid
        }
    except Exception:
        return {"error": "ID invalide"}