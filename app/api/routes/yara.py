"""
api/routers/yara_router.py — Endpoints FastAPI pour l'analyse YARA
"""
import os
import uuid
import shutil
import time

from fastapi import APIRouter, UploadFile, File, HTTPException, Request
from fastapi.responses import JSONResponse
from database.mongodb.connection import Connection as c
from bson import ObjectId
from datetime import datetime
import math
from core.yara_engine import analyze_file, update_rules,get_engine_status, BUILTIN_DIR, BUILTIN_RULES


router = APIRouter()

UPLOAD_DIR   = "storage/yara/uploads"
MAX_FILE_MB  = 50
os.makedirs(UPLOAD_DIR, exist_ok=True)


# Analyse d'un fichier uploadé

@router.post("/yara/scan")
async def scan_file(file: UploadFile = File(...)):
    """
    Upload et analyse un fichier avec YARA.
    Retourne le résultat complet : règles matchées, sévérité, hash SHA256.
    """
    # Vérification taille
    content = await file.read()
    size_mb = len(content) / 1024 / 1024
    if size_mb > MAX_FILE_MB:
        raise HTTPException(
            status_code=413,
            detail=f"Fichier trop volumineux ({size_mb:.1f} MB > {MAX_FILE_MB} MB)"
        )

    # Sauvegarde temporaire avec nom unique
    tmp_id   = str(uuid.uuid4())
    tmp_path = os.path.join(UPLOAD_DIR, tmp_id)
    try:
        with open(tmp_path, "wb") as f:
            f.write(content)

        # Analyse YARA
        result = analyze_file(tmp_path, original_name=file.filename)

        # Sauvegarde en base si malveillant ou pour historique
        scan_id = _save_scan_result(result, file.filename, size_mb)
        result["scan_id"] = scan_id

        return JSONResponse(content=result)

    finally:
        # Toujours supprimer le fichier temporaire
        if os.path.exists(tmp_path):
            os.remove(tmp_path)


 
# Historique des scans
 

@router.get("/yara/history")
async def get_scan_history(
    page:     int = 1,
    limit:    int = 20,
    status:   str = None,   # "malicious" | "clean" | "error"
    severity: str = None,   # "critical" | "high" | "medium" | "low" | "none"
):
    con   = c.get_mongodb_connection("yara_scans")
    query = {}
    if status:   query["status"]   = status
    if severity: query["severity"] = severity

    total = con.count_documents(query)
    scans = list(
        con.find(query)
           .sort("scanned_at", -1)
           .skip((page - 1) * limit)
           .limit(limit)
    )
    return {
        "data":        _serialize(scans),
        "total":       total,
        "page":        page,
        "limit":       limit,
        "total_pages": math.ceil(total / limit) if total > 0 else 1,
        "has_next":    page < math.ceil(total / limit),
        "has_prev":    page > 1,
    }


 
# Détail d'un scan
 

@router.get("/yara/history/{scan_id}")
async def get_scan_detail(scan_id: str):
    try:
        con  = c.get_mongodb_connection("yara_scans")
        scan = con.find_one({"_id": ObjectId(scan_id)})
        if not scan:
            raise HTTPException(status_code=404, detail="Scan introuvable")
        return _serialize([scan])[0]
    except Exception:
        raise HTTPException(status_code=400, detail="ID invalide")


 
# Statistiques
 

@router.get("/yara/stats")
async def get_yara_stats():
    con = c.get_mongodb_connection("yara_scans")
    total     = con.count_documents({})
    malicious = con.count_documents({"status": "malicious"})
    clean     = con.count_documents({"status": "clean"})

    by_severity = list(con.aggregate([
        {"$match": {"status": "malicious"}},
        {"$group": {"_id": "$severity", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
    ]))
    by_category = list(con.aggregate([
        {"$match": {"status": "malicious"}},
        {"$unwind": "$categories"},
        {"$group": {"_id": "$categories", "count": {"$sum": 1}}},
        {"$sort":  {"count": -1}},
        {"$limit": 10},
    ]))
    recent_malicious = list(
        con.find({"status": "malicious"})
           .sort("scanned_at", -1)
           .limit(5)
    )

    return {
        "total_scans":       total,
        "malicious":         malicious,
        "clean":             clean,
        "detection_rate":    round(malicious / total * 100, 1) if total > 0 else 0,
        "by_severity":       _serialize(by_severity),
        "by_category":       _serialize(by_category),
        "recent_malicious":  _serialize(recent_malicious),
    }


 
# Mise à jour manuelle des règles
 

@router.get("/yara/rules/info")
async def get_rules_info():
    from core.yara_engine import get_engine_status, BUILTIN_DIR, BUILTIN_RULES
    compiled_path = "storage/yara/compiled.yarc"
    rules_extract = "storage/yara/raw"
    builtin_dir   = BUILTIN_DIR   # "storage/yara/builtin"

    status = get_engine_status()

    info = {
        "compiled_exists":   os.path.exists(compiled_path),
        "compiled_size_kb":  0,
        "last_updated":      None,
        "categories":        [],
        "rule_files_count":  0,
        "rules_source":      status["rules_source"],   # ← "builtin" | "community" | "none"
        "engine_ready":      status["ready"],
    }

    if os.path.exists(compiled_path):
        stat = os.stat(compiled_path)
        info["compiled_size_kb"] = round(stat.st_size / 1024, 1)
        info["last_updated"]     = datetime.fromtimestamp(stat.st_mtime).isoformat()

    # ─── Compter les règles builtin (toujours présentes) ──────────
    builtin_count = 0
    if os.path.exists(builtin_dir):
        builtin_files = [f for f in os.listdir(builtin_dir)
                         if f.endswith((".yar", ".yara"))]
        builtin_count = len(builtin_files)
        info["categories"].append({
            "name":       "builtin",
            "rule_count": builtin_count,
        })
    else:
        # builtin_dir pas encore créé → compter depuis BUILTIN_RULES en mémoire
        builtin_count = len(BUILTIN_RULES)
        info["categories"].append({
            "name":       "builtin",
            "rule_count": builtin_count,
        })

    info["rule_files_count"] += builtin_count

    #Compter les règles communautaires (si téléchargées)
    if os.path.exists(rules_extract):
        for cat in os.listdir(rules_extract):
            cat_path = os.path.join(rules_extract, cat)
            if os.path.isdir(cat_path):
                n = len([f for f in os.listdir(cat_path)
                         if f.endswith((".yar", ".yara"))])
                if n > 0:
                    info["categories"].append({"name": cat, "rule_count": n})
                    info["rule_files_count"] += n

    return info

 
# Helpers
 

def _save_scan_result(result: dict, filename: str, size_mb: float) -> str:
    try:
        con  = c.get_mongodb_connection("yara_scans")
        doc  = {
            **result,
            "original_filename": filename,
            "file_size_mb":      round(size_mb, 3),
            "scanned_at":        datetime.utcnow(),
        }
        # Convertir scanned_at string en datetime si besoin
        if isinstance(doc.get("scanned_at"), str):
            doc["scanned_at"] = datetime.utcnow()

        inserted = con.insert_one(doc)
        return str(inserted.inserted_id)
    except Exception as e:
        print(f"[!] YARA save error : {e}")
        return ""


def _serialize(docs: list) -> list:
    result = []
    for doc in docs:
        d = dict(doc)
        for k, v in d.items():
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
        result.append(d)
    return result