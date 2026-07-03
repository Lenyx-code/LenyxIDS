"""
api/services/monitoring.py
Endpoints pour le monitoring des machines du réseau.
Le préfixe /api est ajouté dans main.py → routes finales : /api/monitoring/*
"""
import os
import math
from datetime import datetime
from fastapi import APIRouter, Request, HTTPException, Query
from fastapi.responses import StreamingResponse
from database.mongodb.connection import Connection as c
from bson import ObjectId
from api.utils.database import event_generator
from api.utils.broadcast import broadcast
import socket
import threading
from pathlib import Path

router = APIRouter()

AGENT_TOKEN = os.getenv("AGENT_TOKEN", "ids-agent-secret-token")
MONITOR_ALERTS_COLLECTION = "monitor_alerts"   # collection dédiée


# ── Push métriques depuis un agent ───────────────────────────────

@router.post("/monitoring/push")
async def push_metrics(request: Request, body: dict):
    """
    Reçoit les métriques d'un agent Python tournant sur une machine du réseau.
    Stocke en MongoDB et broadcast SSE.
    """
    auth = request.headers.get("Authorization", "")
    if AGENT_TOKEN and auth != f"Bearer {AGENT_TOKEN}":
        raise HTTPException(status_code=401, detail="Token invalide")

    if not body.get("hostname"):
        raise HTTPException(status_code=422, detail="hostname requis")

    try:
        con = c.get_mongodb_connection("monitoring_metrics")
        doc = {
            **body,
            "received_at": datetime.utcnow(),
        }
        if isinstance(doc.get("timestamp"), str):
            try:
                doc["timestamp"] = datetime.fromisoformat(doc["timestamp"])
            except Exception:
                doc["timestamp"] = datetime.utcnow()

        con.insert_one(doc)

        # Broadcast SSE métriques
        try:
            from api.utils.broadcast import broadcast
            metrics_lite = {k: v for k, v in body.items() if k != "processes"}
            top = sorted(body.get("processes", []), key=lambda p: p.get("cpu_pct", 0), reverse=True)[:5]
            metrics_lite["top_processes"] = top
            broadcast("monitoring", metrics_lite)
        except Exception as e:
            print(f"[!] Monitoring broadcast error : {e}")

        # Détection comportementale → alertes dans monitor_alerts
        _analyse_push(body)

        return {"ok": True}

    except HTTPException:
        raise
    except Exception as e:
        print(f"[!] Monitoring push error : {e}")
        raise HTTPException(status_code=500, detail=str(e))


# ── SSE métriques temps réel ──────────────────────────────────────

@router.get("/monitoring/stream")
async def stream_monitoring(request: Request):
    return StreamingResponse(
        event_generator(request, "monitoring"),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "Connection":        "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )


# ── SSE alertes monitoring temps réel ────────────────────────────

@router.get("/monitoring/alerts/stream")
async def stream_monitor_alerts(request: Request):
    """
    SSE dédié aux alertes système (monitor_alerts).
    Le client se connecte et reçoit les nouvelles alertes en push.
    """
    return StreamingResponse(
        event_generator(request, "monitor_alerts"),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "Connection":        "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )



# ── Broadcast depuis agent MongoBackend ───────────────────────────
# L'agent écrit directement en MongoDB, puis appelle ces endpoints
# pour déclencher le broadcast SSE sans passer par /push.

@router.post("/monitoring/broadcast-metrics")
async def broadcast_metrics(request: Request, body: dict):
    """Reçoit les métriques allégées de l'agent et les broadcast sur le canal SSE."""
    auth = request.headers.get("Authorization", "")
    if AGENT_TOKEN and auth != f"Bearer {AGENT_TOKEN}":
        raise HTTPException(status_code=401, detail="Token invalide")
    try:
        from api.utils.broadcast import broadcast
        broadcast("monitoring", body)
        return {"ok": True}
    except Exception as e:
        return {"ok": False, "error": str(e)}


@router.post("/monitoring/broadcast-alert")
async def broadcast_alert(request: Request, body: dict):
    auth = request.headers.get("Authorization", "")
    if AGENT_TOKEN and auth != f"Bearer {AGENT_TOKEN}":
        raise HTTPException(status_code=401, detail="Token invalide")

    try:
        if "_id" in body:
            body["_id"] = str(body["_id"])

        if "id" not in body:
            body["id"] = body.get("_id") or str(ObjectId())

        print("Broadcast alert:", body)

        broadcast("monitor_alerts", body)

        return {"ok": True}
    except Exception as e:
        print("Broadcast error:", e)
        return {"ok": False, "error": str(e)}


# ── Hosts ─────────────────────────────────────────────────────────

@router.get("/monitoring/hosts")
async def get_hosts():
    """Retourne le dernier snapshot de métriques pour chaque machine."""
    con = c.get_mongodb_connection("monitoring_metrics")
    from datetime import timedelta
    cutoff = datetime.utcnow() - timedelta(hours=2)

    pipeline = [
        {"$match": {"received_at": {"$gte": cutoff}}},
        {"$sort": {"received_at": -1}},
        {"$group": {
            "_id":              "$hostname",
            "hostname":         {"$first": "$hostname"},
            "os":               {"$first": "$os"},
            "os_version":       {"$first": "$os_version"},
            "last_seen":        {"$first": "$received_at"},
            "timestamp":        {"$first": "$timestamp"},
            "cpu_pct":          {"$first": "$cpu_pct"},
            "cpu_count":        {"$first": "$cpu_count"},
            "ram_pct":          {"$first": "$ram_pct"},
            "ram_used_mb":      {"$first": "$ram_used_mb"},
            "ram_total_mb":     {"$first": "$ram_total_mb"},
            "disk_pct":         {"$first": "$disk_pct"},
            "disk_used_gb":     {"$first": "$disk_used_gb"},
            "disk_total_gb":    {"$first": "$disk_total_gb"},
            "net_sent_mb":      {"$first": "$net_sent_mb"},
            "net_recv_mb":      {"$first": "$net_recv_mb"},
            "open_connections": {"$first": "$open_connections"},
            "connections":      {"$first": "$connections"},
            "process_count":    {"$first": "$process_count"},
            "processes":        {"$first": "$processes"},
            "ip_main":          {"$first": "$ip_main"},
            "ip_interfaces":    {"$first": "$ip_interfaces"},
        }},
        {"$sort": {"hostname": 1}},
    ]
    hosts = list(con.aggregate(pipeline))
    return {"hosts": _serialize(hosts)}


@router.get("/monitoring/hosts/{hostname}/history")
async def get_host_history(hostname: str, limit: int = 60):
    con  = c.get_mongodb_connection("monitoring_metrics")
    data = list(
        con.find({"hostname": hostname}, {
            "timestamp": 1, "received_at": 1,
            "cpu_pct": 1, "ram_pct": 1, "disk_pct": 1,
            "open_connections": 1,
        })
           .sort("received_at", -1)
           .limit(limit)
    )
    data.reverse()
    return {"hostname": hostname, "history": _serialize(data)}


# ── Alertes système ───────────────────────────────────────────────

@router.get("/monitoring/alerts")
async def get_system_alerts(
    page:         int = 1,
    limit:        int = 20,
    anomaly_type: str = None,
    severity:     str = None,
    hostname:     str = None,
):
    """
    Liste paginée des alertes système.
    Stockées dans la collection `monitor_alerts`.
    """
    con   = c.get_mongodb_connection(MONITOR_ALERTS_COLLECTION)
    query = {"attack_type": "SYSTEM_ANOMALY"}

    if anomaly_type: query["anomaly_type"] = anomaly_type
    if severity:     query["severity"]     = severity
    if hostname:     query["$or"] = [
        {"ip_src": {"$regex": hostname, "$options": "i"}},
        {"agent_hostname": {"$regex": hostname, "$options": "i"}},
    ]

    total  = con.count_documents(query)
    alerts = list(
        con.find(query)
           .sort("detection_time", -1)
           .skip((page - 1) * limit)
           .limit(limit)
    )
    return {
        "data":        _serialize(alerts),
        "total":       total,
        "page":        page,
        "limit":       limit,
        "total_pages": math.ceil(total / limit) if total > 0 else 1,
    }


@router.patch("/monitoring/alerts/{alert_id}/status")
async def update_alert_status(alert_id: str, body: dict):
    """Met à jour le statut d'une alerte (open / reviewed / closed)."""
    status = body.get("status")
    if status not in ("open", "reviewed", "closed"):
        raise HTTPException(status_code=422, detail="Statut invalide")
    try:
        con = c.get_mongodb_connection(MONITOR_ALERTS_COLLECTION)
        result = con.update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {"status": status, "updated_at": datetime.utcnow()}},
        )
        if result.matched_count == 0:
            raise HTTPException(status_code=404, detail="Alerte introuvable")
        return {"ok": True, "status": status}
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


# ── Baseline FileWatcher ──────────────────────────────────────────

@router.post("/monitoring/baseline/rebuild")
async def rebuild_baseline():
    try:
        from app.core.monitoring.file_watcher import get_file_watcher
        result = get_file_watcher().rebuild_baseline()
        return {"success": True, "message": "Baseline reconstruite", **result}
    except Exception as e:
        return {"success": False, "error": str(e)}


@router.get("/monitoring/baseline/diff")
async def baseline_diff():
    """Retourne les fichiers modifiés depuis la dernière baseline."""
    try:
        from app.core.monitoring.file_watcher import get_file_watcher
        changes = get_file_watcher().check_diff()
        return {"changes": changes, "count": len(changes)}
    except Exception as e:
        return {"changes": [], "error": str(e)}



def _save_monitor_alert(anomaly_type: str, detail: str, severity: str, hostname: str, **kwargs):
    """
    Sauvegarde l'alerte en MongoDB (utilisé en mode API ou analyse locale du backend)
    et la diffuse instantanément au frontend.
    """
    try:
        con = c.get_mongodb_connection(MONITOR_ALERTS_COLLECTION)
        d = {
            "anomaly_type": anomaly_type,
            "detail": detail,
            "severity": severity,
            "agent_hostname": hostname,
            "detection_time": datetime.utcnow().isoformat(),
            **kwargs
        }
        res = con.insert_one(d)
        
        # Normalisation des IDs pour les composants React Toasts
        d["_id"] = str(res.inserted_id)
        d["id"] = str(res.inserted_id)
        
        # UTILISATION DU BROADCAST GLOBAL
        broadcast("monitor_alerts", d)
        print(f"[+] Alerte monitoring poussée sur le flux : {anomaly_type}")
    except Exception as e:
        print(f"[!] Erreur _save_monitor_alert: {e}")


def _analyse_push(data: dict):
    """Détecte les anomalies dans les métriques reçues."""
    hostname = data.get("hostname", "unknown")

    # CPU > 90 %
    if (data.get("cpu_pct") or 0) > 90:
        _save_monitor_alert(
            "CPU_SPIKE",
            f"CPU à {data['cpu_pct']}% sur {hostname}",
            "high", hostname,
        )

    # RAM > 95 %
    if (data.get("ram_pct") or 0) > 95:
        _save_monitor_alert(
            "RAM_EXHAUSTION",
            f"RAM à {data['ram_pct']}% ({data.get('ram_used_mb')} MB / {data.get('ram_total_mb')} MB)",
            "high", hostname,
        )

    # Disque > 95 %
    if (data.get("disk_pct") or 0) > 95:
        _save_monitor_alert(
            "DISK_FULL",
            f"Disque à {data['disk_pct']}% sur {hostname}",
            "high", hostname,
        )

    # Processus suspects
    for proc in data.get("processes", []):
        if proc.get("suspicious"):
            _save_monitor_alert(
                "SUSPICIOUS_COMMAND",
                f"Commande suspecte : pid={proc.get('pid')} user={proc.get('user')} "
                f"cmd='{proc.get('cmdline', '')[:150]}'",
                "critical", hostname,
                process_name=proc.get("name"),
                process_pid=proc.get("pid"),
                process_user=proc.get("user"),
                process_cmd=proc.get("cmdline", "")[:200],
            )
        elif proc.get("unknown_root") and (proc.get("cpu_pct") or 0) > 10:
            _save_monitor_alert(
                "UNEXPECTED_ROOT_PROC",
                f"Processus root inconnu : '{proc.get('name')}' pid={proc.get('pid')} "
                f"CPU={proc.get('cpu_pct')}%",
                "high", hostname,
                process_name=proc.get("name"),
                process_pid=proc.get("pid"),
                process_user=proc.get("user"),
                process_cpu=proc.get("cpu_pct"),
            )
        elif proc.get("overloaded"):
            _save_monitor_alert(
                "PROCESS_OVERLOAD",
                f"Processus surchargé : '{proc.get('name')}' CPU={proc.get('cpu_pct')}% "
                f"RAM={proc.get('mem_pct')}%",
                "medium", hostname,
                process_name=proc.get("name"),
                process_pid=proc.get("pid"),
                process_user=proc.get("user"),
                process_cpu=proc.get("cpu_pct"),
                process_mem=proc.get("mem_pct"),
                overload_cycles=proc.get("overload_cycles", 1),
            )
# Ajouter dans monitoring.py

@router.post("/monitoring/file-changes")
async def push_file_change(body: dict):
    """Reçoit et stocke un changement fichier détecté par Watchdog."""
    if not body.get("hostname") or not body.get("file_path"):
        raise HTTPException(status_code=422, detail="hostname et file_path requis")

    con = c.get_mongodb_connection("file_changes")
    doc = {**body, "received_at": datetime.utcnow()}
    if isinstance(doc.get("timestamp"), str):
        try:
            doc["timestamp"] = datetime.fromisoformat(doc["timestamp"])
        except Exception:
            doc["timestamp"] = datetime.utcnow()

    result = con.insert_one(doc)
    doc["_id"] = str(result.inserted_id)

    # Broadcaster pour que la vue Monitoring se mette à jour en temps réel
    broadcast("monitoring", {"file_change": doc})

    return {"ok": True, "id": str(result.inserted_id)}


@router.get("/monitoring/hosts/{hostname}/file-changes")
async def get_file_changes(
    hostname: str,
    page:        int = Query(default=1, ge=1),
    limit:       int = Query(default=50, ge=1, le=200),
    change_type: str = Query(default=None),   # "created"|"modified"|"deleted"
):
    con   = c.get_mongodb_connection("file_changes")
    query = {"hostname": hostname}
    if change_type:
        query["change_type"] = change_type

    total   = con.count_documents(query)
    changes = list(
        con.find(query)
           .sort("received_at", -1)
           .skip((page - 1) * limit)
           .limit(limit)
    )
    return {
        "data":        _serialize(changes),
        "total":       total,
        "page":        page,
        "limit":       limit,
        "total_pages": math.ceil(total / limit) if total > 0 else 1,
    }   

# ── Sérialisation ─────────────────────────────────────────────────

def _serialize(docs: list) -> list:
    out = []
    for doc in docs:
        d = dict(doc)
        for k, v in list(d.items()):
            if isinstance(v, ObjectId):
                d[k] = str(v)
            elif isinstance(v, datetime):
                d[k] = v.isoformat()
            elif isinstance(v, list):
                d[k] = [
                    {kk: str(vv) if isinstance(vv, (ObjectId, datetime)) else vv
                     for kk, vv in item.items()}
                    if isinstance(item, dict) else item
                    for item in v
                ]
        out.append(d)
    return out