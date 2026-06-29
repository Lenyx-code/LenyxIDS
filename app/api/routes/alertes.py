from fastapi import APIRouter, Request, Query
from fastapi.responses import StreamingResponse
from api.utils.database import event_generator
from database.mongodb.connection import Connection as c
from database.mongodb.repository import Repository
from bson import ObjectId
from datetime import datetime
import math

router = APIRouter()


@router.get("/stream/alerts", tags=["Stream"],
    response_class=StreamingResponse,
    responses={200: {"content": {"text/event-stream": {}}}})
async def stream_alerts(request: Request):
    return StreamingResponse(
        event_generator(request, "alerts"),
        media_type="text/event-stream",
        headers={
            "Cache-Control":     "no-cache",
            "Connection":        "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

@router.get("/stream/count", tags=["Stream"])
async def stream_alerts_count(request: Request):
    async def generator():
        import asyncio
        con = c.get_mongodb_connection("alerts")
        while True:
            if await request.is_disconnected():
                break
            count = con.count_documents({"status": "open"})
            yield f"data: {count}\n\n"
            await asyncio.sleep(5)
    return StreamingResponse(generator(), media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "Connection": "keep-alive"})



@router.get("/alerts/stats/summary", tags=["Alertes"])
async def get_alerts_stats():
    con = c.get_mongodb_connection("alerts")

    total      = con.count_documents({})
    open_count = con.count_documents({"status": "open"})

    by_type = list(con.aggregate([
        {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}}
    ]))
    by_severity = list(con.aggregate([
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}}
    ]))
    by_ip = list(con.aggregate([
        {"$group": {"_id": "$ip_src", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
        {"$limit": 5}
    ]))

    return {
        "total":       total,
        "open":        open_count,
        "by_type":     _serialize(by_type),
        "by_severity": _serialize(by_severity),
        "top_ips":     _serialize(by_ip),
    }

@router.get("/alerts", tags=["Alertes"])
async def get_all_alerts(
    page:        int = Query(default=1,   ge=1),
    limit:       int = Query(default=20,  ge=1, le=100),
    attack_type: str = Query(default=None),
    ip_src:      str = Query(default=None),
    ip_dst:      str = Query(default=None),
    severity:    str = Query(default=None),
    status:      str = Query(default=None),
    group_by:    str = Query(default=None),
    sort_by:     str = Query(default="detection_time"),
    sort_order:  int = Query(default=-1),
):
    con   = c.get_mongodb_connection("alerts")
    query = {}

    if attack_type: query["attack_type"] = attack_type
    if ip_src:      query["ip_src"]      = {"$regex": ip_src, "$options": "i"}
    if ip_dst:      query["ip_dst"]      = {"$regex": ip_dst, "$options": "i"}
    if severity:    query["severity"]    = severity
    if status:      query["status"]      = status

    if group_by:
        pipeline = [
            {"$match": query},
            {"$group": {
                "_id":        f"${group_by}",
                "count":      {"$sum": 1},
                "last":       {"$max": "$detection_time"},
                "severities": {"$addToSet": "$severity"},
                "ips":        {"$addToSet": "$ip_src"},
            }},
            {"$sort":  {"count": -1}},
            {"$skip":  (page - 1) * limit},
            {"$limit": limit}
        ]
        return {
            "grouped_by": group_by,
            "data":       _serialize(list(con.aggregate(pipeline))),
            "page":       page,
            "limit":      limit,
        }

    total  = con.count_documents(query)
    alerts = list(
        con.find(query)
           .sort(sort_by, sort_order)
           .skip((page - 1) * limit)
           .limit(limit)
    )

    return {
        "data":        _serialize(alerts),
        "total":       total,
        "page":        page,
        "limit":       limit,
        "total_pages": math.ceil(total / limit) if total > 0 else 1,
        "has_next":    page < math.ceil(total / limit),
        "has_prev":    page > 1,
    }


@router.get("/alerts/{alert_id}", tags=["Alertes"]) 
async def get_alert_by_id(alert_id: str):
    try:
        con   = c.get_mongodb_connection("alerts")
        alert = con.find_one({"_id": ObjectId(alert_id)})
        if not alert:
            return {"error": "Alerte non trouvée"}
        return {
            "data":            _serialize([alert])[0],
            "integrity_valid": Repository.verify_integrity(dict(alert))
        }
    except Exception:
        return {"error": "ID invalide"}

@router.patch("/alerts/{alert_id}/status", tags=["Alertes"])
async def update_alert_status(alert_id: str, body: dict):
    new_status = body.get("status")
    if new_status not in ("open", "reviewed", "closed"):
        return {"error": "Statut invalide"}
    try:
        con = c.get_mongodb_connection("alerts")
        con.update_one(
            {"_id": ObjectId(alert_id)},
            {"$set": {"status": new_status, "updated_at": datetime.utcnow()}}
        )
        return {"success": True, "status": new_status}
    except Exception:
        return {"error": "ID invalide"}

# Serialisation

def _serialize(docs: list) -> list:
    result = []
    for doc in docs:
        d = dict(doc)
        result.append(_serialize_value(d))
    return result

def _serialize_value(obj):
    if isinstance(obj, dict):
        return {k: _serialize_value(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [_serialize_value(i) for i in obj]
    elif isinstance(obj, ObjectId):
        return str(obj)
    elif isinstance(obj, datetime):
        return obj.isoformat()
    else:
        return obj