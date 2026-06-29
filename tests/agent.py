"""
agent.py — Agent de monitoring avec analyse locale + sauvegarde MongoDB
Mode mongo : écrit directement en MongoDB + notifie le backend pour le SSE
Mode api   : push via l'API HTTP (prod)
"""

import argparse
import hashlib
import json
import os
import platform
import socket
import sys
import time
from datetime import datetime, timezone

try:
    import psutil
except ImportError:
    print("[!] psutil manquant — pip install psutil")
    sys.exit(1)

try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False

try:
    from pymongo import MongoClient
    MONGO_OK = True
except ImportError:
    MONGO_OK = False

#  Configuration 

DEFAULT_API_URL   = "http://172.20.0.2:8000"
DEFAULT_TOKEN     = "ids-agent-secret-token"
DEFAULT_MONGO_URI = "mongodb://172.20.0.6:27017/"
DEFAULT_DB        = "cyber_forensic_db"
DEFAULT_INTERVAL  = 5
MAX_RETRIES       = 3
RETRY_DELAY       = 5

THRESHOLDS = {
    "cpu_critical":      90.0,
    "ram_critical":      95.0,
    "disk_critical":     95.0,
    "proc_cpu_critical": 80.0,
    "proc_cpu_cycles":   3,
}

COOLDOWN = {
    "CPU_SPIKE":              60,
    "RAM_EXHAUSTION":         60,
    "DISK_FULL":             300,
    "SUSPICIOUS_COMMAND":     30,
    "UNEXPECTED_ROOT_PROC":   60,
    "SUSPICIOUS_CONNECTION": 120,
    "PROCESS_OVERLOAD":       90,
    "FILE_CHANGE":            10,
}

KNOWN_LINUX = {
    "python3", "python", "apache2", "nginx", "sshd", "mysqld", "mongod",
    "uvicorn", "bash", "sh", "systemd", "cron", "rsyslogd", "dockerd",
    "containerd", "node", "java", "postgres", "redis-server",
}
KNOWN_WINDOWS = {
    "python.exe", "pythonw.exe", "svchost.exe", "lsass.exe", "explorer.exe",
    "taskmgr.exe", "cmd.exe", "powershell.exe", "wininit.exe", "winlogon.exe",
    "csrss.exe", "smss.exe", "services.exe", "spoolsv.exe", "System", "Idle",
    "RuntimeBroker.exe", "SearchHost.exe", "sihost.exe", "fontdrvhost.exe",
}

SUSPICIOUS_CMDS = [
    "nc ", "netcat", "ncat", "/dev/tcp", "/dev/udp",
    "base64 -d", "curl | bash", "wget | bash", "wget -o- |",
    "python -c", "perl -e", "ruby -e",
    "chmod +s", "chmod 4777", "chmod 777 /",
    "whoami", "sudo su", "pkexec",
    "/etc/shadow", "/etc/passwd", "ntds.dit",
    "mimikatz", "sekurlsa", "hashdump", "lazagne",
    "powershell -enc", "powershell -e ", "mshta", "wscript", "cscript",
    "reg add hklm", "net user /add", "net localgroup administrators",
]

SUSPICIOUS_REMOTE_PORTS = {4444, 1337, 31337, 8888, 9999, 6666, 5555}

WATCH_PATHS = {
    "linux": [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/ssh/sshd_config", "/etc/hosts",
        "/root/.bashrc", "/root/.ssh/authorized_keys",
    ],
    "windows": [
        "C:\\Windows\\System32\\drivers\\etc\\hosts",
        "C:\\Windows\\System32\\config\\SAM",
    ],
}


#  Collecte IP réseau 

def get_network_ips() -> dict:
    ips = {}
    try:
        for iface, addrs in psutil.net_if_addrs().items():
            for addr in addrs:
                if addr.family == socket.AF_INET:
                    ips[iface] = addr.address
    except Exception:
        pass
    main_ip = next(
        (ip for iface, ip in ips.items() if not ip.startswith("127.")),
        "127.0.0.1"
    )
    return {"all": ips, "main": main_ip}


#  Watchdog fichiers ─

class FileWatchdog:

    def __init__(self, os_type: str):
        key   = "windows" if os_type == "Windows" else "linux"
        paths = WATCH_PATHS.get(key, [])
        self._baseline: dict = {}
        self._build_baseline(paths)

    def _build_baseline(self, paths: list):
        for path in paths:
            try:
                st = os.stat(path)
                self._baseline[path] = {"mtime": st.st_mtime, "size": st.st_size}
            except (FileNotFoundError, Exception):
                pass
        print(f"[*] FileWatchdog : baseline construite ({len(self._baseline)} fichiers)")

    def check(self) -> list[dict]:
        changes = []
        for path, base in list(self._baseline.items()):
            try:
                st = os.stat(path)
                if st.st_mtime != base["mtime"] or st.st_size != base["size"]:
                    change_type = "TRUNCATED" if st.st_size == 0 and base["size"] > 0 else "MODIFIED"
                    changes.append({
                        "path": path, "change_type": change_type,
                        "old_size": base["size"], "new_size": st.st_size,
                    })
                    self._baseline[path] = {"mtime": st.st_mtime, "size": st.st_size}
            except FileNotFoundError:
                changes.append({"path": path, "change_type": "DELETED",
                                 "old_size": base["size"], "new_size": 0})
                self._baseline.pop(path, None)
            except Exception:
                pass
        return changes


#  Watchdog processus

class ProcessWatchdog:

    def __init__(self):
        self._overload_streaks: dict[int, int] = {}

    def check(self, processes: list[dict]) -> list[dict]:
        threshold  = THRESHOLDS["proc_cpu_critical"]
        min_cycles = THRESHOLDS["proc_cpu_cycles"]
        overloaded   = []
        current_pids = set()

        for proc in processes:
            pid     = proc.get("pid")
            cpu_pct = proc.get("cpu_pct", 0)
            if pid is None:
                continue
            current_pids.add(pid)
            if cpu_pct >= threshold:
                self._overload_streaks[pid] = self._overload_streaks.get(pid, 0) + 1
                if self._overload_streaks[pid] >= min_cycles:
                    overloaded.append({**proc, "overload_cycles": self._overload_streaks[pid]})
            else:
                self._overload_streaks.pop(pid, None)

        for pid in list(self._overload_streaks):
            if pid not in current_pids:
                del self._overload_streaks[pid]

        return overloaded


#Collecte des métriques

class MetricsCollector:

    def __init__(self):
        self.hostname   = socket.gethostname()
        self.os_type    = platform.system()
        self.os_version = platform.version()[:80]
        self._known     = KNOWN_WINDOWS if self.os_type == "Windows" else KNOWN_LINUX
        self._net_ips   = get_network_ips()

    def collect(self) -> dict:
        cpu   = psutil.cpu_percent(interval=1)
        ram   = psutil.virtual_memory()
        disk  = self._disk()
        net   = psutil.net_io_counters()
        conns = self._connections()
        procs = self._processes()
        return {
            "hostname":         self.hostname,
            "os":               self.os_type,
            "os_version":       self.os_version,
            "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "ip_main":          self._net_ips["main"],
            "ip_interfaces":    self._net_ips["all"],
            "cpu_pct":          cpu,
            "cpu_count":        psutil.cpu_count(logical=True),
            "ram_pct":          ram.percent,
            "ram_used_mb":      round(ram.used  / 1024 / 1024, 1),
            "ram_total_mb":     round(ram.total / 1024 / 1024, 1),
            "disk_pct":         disk["pct"],
            "disk_used_gb":     disk["used_gb"],
            "disk_total_gb":    disk["total_gb"],
            "net_sent_mb":      round(net.bytes_sent / 1024 / 1024, 2),
            "net_recv_mb":      round(net.bytes_recv / 1024 / 1024, 2),
            "open_connections": conns["count"],
            "connections":      conns["details"],
            "processes":        procs,
            "process_count":    len(procs),
        }

    def refresh_ips(self):
        self._net_ips = get_network_ips()

    def _disk(self) -> dict:
        path = "C:\\" if self.os_type == "Windows" else "/"
        try:
            d = psutil.disk_usage(path)
            return {"pct": d.percent,
                    "used_gb":  round(d.used  / 1024 ** 3, 2),
                    "total_gb": round(d.total / 1024 ** 3, 2)}
        except Exception:
            return {"pct": 0.0, "used_gb": 0.0, "total_gb": 0.0}

    def _connections(self) -> dict:
        try:
            conns = psutil.net_connections(kind="inet")
            details = [
                {"laddr":  f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                 "raddr":  f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                 "status": c.status, "pid": c.pid}
                for c in conns[:20]
            ]
            return {"count": len(conns), "details": details}
        except (psutil.AccessDenied, Exception):
            return {"count": 0, "details": []}

    def _processes(self) -> list:
        procs = []
        for p in psutil.process_iter([
            "pid", "name", "username", "cmdline",
            "cpu_percent", "memory_percent", "status",
        ]):
            try:
                info    = p.info
                name    = info.get("name") or ""
                cmdline = " ".join(info.get("cmdline") or [])
                user    = info.get("username") or ""
                cpu_pct = round(info.get("cpu_percent") or 0.0, 1)
                mem_pct = round(info.get("memory_percent") or 0.0, 2)
                suspicious   = any(s in cmdline.lower() for s in SUSPICIOUS_CMDS)
                root_users   = {"root", "SYSTEM", "NT AUTHORITY\\SYSTEM"}
                unknown_root = (user in root_users and name not in self._known and cpu_pct > 5)
                procs.append({
                    "pid": info.get("pid"), "name": name, "user": user,
                    "cmdline": cmdline[:300], "cpu_pct": cpu_pct, "mem_pct": mem_pct,
                    "status": info.get("status") or "",
                    "suspicious": suspicious, "unknown_root": unknown_root, "overloaded": False,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
        procs.sort(key=lambda x: (not x["suspicious"], not x["unknown_root"], -x["cpu_pct"]))
        return procs[:50]


# Analyse locale

class LocalAnalyser:

    def __init__(self):
        self._cooldowns: dict = {}
        self._cpu_streak = 0
        self._ram_streak = 0

    def analyse(self, metrics: dict, file_changes: list, overloaded_procs: list) -> list[dict]:
        alerts   = []
        hostname = metrics.get("hostname", "unknown")

        if metrics.get("cpu_pct", 0) >= THRESHOLDS["cpu_critical"]:
            self._cpu_streak += 1
            if self._cpu_streak >= 3 and self._can_alert("CPU_SPIKE"):
                alerts.append(self._build(hostname, "CPU_SPIKE", "high",
                    f"CPU à {metrics['cpu_pct']}% depuis {3 * DEFAULT_INTERVAL}s"))
                self._cpu_streak = 0
        else:
            self._cpu_streak = 0

        if metrics.get("ram_pct", 0) >= THRESHOLDS["ram_critical"]:
            self._ram_streak += 1
            if self._ram_streak >= 2 and self._can_alert("RAM_EXHAUSTION"):
                alerts.append(self._build(hostname, "RAM_EXHAUSTION", "high",
                    f"RAM à {metrics['ram_pct']}% ({metrics.get('ram_used_mb')} MB / {metrics.get('ram_total_mb')} MB)"))
                self._ram_streak = 0
        else:
            self._ram_streak = 0

        if metrics.get("disk_pct", 0) >= THRESHOLDS["disk_critical"]:
            if self._can_alert("DISK_FULL"):
                alerts.append(self._build(hostname, "DISK_FULL", "critical",
                    f"Disque à {metrics['disk_pct']}% ({metrics.get('disk_used_gb')} GB / {metrics.get('disk_total_gb')} GB)"))

        for proc in metrics.get("processes", []):
            if proc.get("suspicious"):
                key = f"SUSPICIOUS_COMMAND_{proc.get('pid')}"
                if self._can_alert(key, COOLDOWN["SUSPICIOUS_COMMAND"]):
                    alerts.append(self._build(hostname, "SUSPICIOUS_COMMAND", "critical",
                        f"Commande suspecte : pid={proc.get('pid')} user={proc.get('user')} cmd='{proc.get('cmdline','')[:150]}'",
                        extra={"process_name": proc.get("name"), "process_pid": proc.get("pid"),
                               "process_user": proc.get("user"), "process_cmd": proc.get("cmdline","")[:200]}))
                    print(f"[!!!] SUSPECT pid={proc.get('pid')} : {proc.get('cmdline','')[:80]}")
            elif proc.get("unknown_root") and (proc.get("cpu_pct") or 0) > 10:
                key = f"UNEXPECTED_ROOT_{proc.get('pid')}"
                if self._can_alert(key, COOLDOWN["UNEXPECTED_ROOT_PROC"]):
                    alerts.append(self._build(hostname, "UNEXPECTED_ROOT_PROC", "high",
                        f"Processus root inconnu : '{proc.get('name')}' pid={proc.get('pid')} CPU={proc.get('cpu_pct')}%",
                        extra={"process_name": proc.get("name"), "process_pid": proc.get("pid"),
                               "process_user": proc.get("user"), "process_cpu": proc.get("cpu_pct")}))

        for proc in overloaded_procs:
            key = f"PROCESS_OVERLOAD_{proc.get('pid')}"
            if self._can_alert(key, COOLDOWN["PROCESS_OVERLOAD"]):
                alerts.append(self._build(hostname, "PROCESS_OVERLOAD", "medium",
                    f"Processus '{proc.get('name')}' surchargé : CPU={proc.get('cpu_pct')}% depuis {proc.get('overload_cycles',0)} cycles",
                    extra={"process_name": proc.get("name"), "process_pid": proc.get("pid"),
                           "process_user": proc.get("user"), "process_cpu": proc.get("cpu_pct"),
                           "process_mem": proc.get("mem_pct"), "overload_cycles": proc.get("overload_cycles")}))
                print(f"[!] OVERLOAD '{proc.get('name')}' pid={proc.get('pid')} CPU={proc.get('cpu_pct')}%")

        for change in file_changes:
            key = f"FILE_CHANGE_{change['path']}"
            if self._can_alert(key, COOLDOWN["FILE_CHANGE"]):
                alerts.append(self._build(hostname, "FILE_CHANGE", "critical",
                    f"Fichier {change['change_type']} : {change['path']} ({change.get('old_size',0)} → {change.get('new_size',0)} bytes)",
                    extra={"file_path": change["path"], "change_type": change["change_type"],
                           "old_size": change.get("old_size"), "new_size": change.get("new_size")}))
                print(f"[!!!] FILE {change['change_type']} : {change['path']}")

        for conn in metrics.get("connections", []):
            raddr = conn.get("raddr", "")
            if not raddr:
                continue
            try:
                if int(raddr.split(":")[-1]) in SUSPICIOUS_REMOTE_PORTS:
                    key = f"SUSPICIOUS_CONNECTION_{raddr}"
                    if self._can_alert(key, COOLDOWN["SUSPICIOUS_CONNECTION"]):
                        alerts.append(self._build(hostname, "SUSPICIOUS_CONNECTION", "critical",
                            f"Connexion vers port suspect : {raddr} (pid={conn.get('pid')})",
                            extra={"remote_addr": raddr, "local_addr": conn.get("laddr"),
                                   "conn_pid": conn.get("pid"), "conn_status": conn.get("status")}))
            except (ValueError, IndexError):
                pass

        return alerts

    def _can_alert(self, key: str, cooldown: int = None) -> bool:
        cd  = cooldown or COOLDOWN.get(key, 60)
        now = time.time()
        if now - self._cooldowns.get(key, 0) >= cd:
            self._cooldowns[key] = now
            return True
        return False

    @staticmethod
    def _hash(data: dict) -> str:
        exclude = {"integrity_hash", "_id"}
        clean   = {k: v for k, v in data.items() if k not in exclude}
        return hashlib.sha256(json.dumps(clean, sort_keys=True, default=str).encode()).hexdigest()

    def _build(self, hostname: str, anomaly_type: str,
               severity: str, detail: str, extra: dict = None) -> dict:
        doc = {
            "detection_time": datetime.now(timezone.utc).isoformat(),
            "attack_type":    "SYSTEM_ANOMALY",
            "anomaly_type":   anomaly_type,
            "severity":       severity,
            "ip_src":         hostname,
            "ip_dst":         hostname,
            "iface":          "system",
            "status":         "open",
            "detail":         detail,
            "agent_hostname": hostname,
            **(extra or {}),
        }
        doc["integrity_hash"] = self._hash(doc)
        return doc


#Backend Mongo

class MongoBackend:
    """
    Écrit directement en MongoDB, puis notifie le backend FastAPI
    pour qu'il broadcast sur les canaux SSE (métriques + alertes).
    """

    def __init__(self, uri: str, db_name: str = DEFAULT_DB,
                 api_url: str = DEFAULT_API_URL, token: str = DEFAULT_TOKEN):
        if not MONGO_OK:
            print("[!] pymongo manquant — pip install pymongo")
            sys.exit(1)
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        client.admin.command("ping")
        self._db = client[db_name]

        self._api_base = api_url.rstrip("/")
        self._headers  = {
            "Authorization": f"Bearer {token}",
            "Content-Type":  "application/json",
        }
        self._session = requests.Session() if REQUESTS_OK else None
        if self._session:
            self._session.headers.update(self._headers)

        print(f"[+] MongoDB connecté : {uri} → {db_name}")
        print(f"[+] Backend SSE      : {self._api_base}")

    # agent.py (Extrait de la classe MongoBackend ou de la routine d'alerte)

    def _broadcast(self, alert_dict: dict):
        """
        Envoie l'alerte fraîchement créée au backend central pour déclencher le SSE instantané.
        """
        if not REQUESTS_OK:
            return

        try:
            # Sécurité de copie pour éviter de corrompre l'objet d'origine
            data = dict(alert_dict)
            
            # Conversion de l'ObjectId de MongoDB en chaîne exploitable
            if "_id" in data:
                data["_id"] = str(data["_id"])
                
            # On s'assure que le champ 'id' existe pour l'unification Frontend
            data["id"] = data.get("id") or data.get("_id")
            
            # Conversion propre des formats temporels si nécessaire
            if isinstance(data.get("detection_time"), datetime):
                data["detection_time"] = data["detection_time"].isoformat()
            else:
                data["detection_time"] = str(data.get("detection_time", ""))

            # Requête vers l'endpoint ajusté ci-dessus
            url = f"{self.api_url}/api/monitoring/broadcast-alert"
            headers = {"Authorization": f"Bearer {self.token}"}
            
            res = requests.post(url, json=data, headers=headers, timeout=3)
            if res.status_code != 200:
                print(f"[!] Échec de notification broadcast au backend ({res.status_code})")
                
        except Exception as e:
            print(f"[!] Erreur de transmission de l'alerte à l'API : {e}")

    #métriques

    def save_metrics(self, metrics: dict):
        # 1. Persistance MongoDB
        self._db["monitoring_metrics"].insert_one({
            **metrics,
            "received_at": datetime.now(timezone.utc),
        })
        # 2. Broadcast SSE métriques (version allégée)
        self._post("/api/monitoring/broadcast-metrics", self._lite(metrics))

    # alertes

    def _save_alert(self, anomaly_type: str, detail: str, severity: str, **kwargs):
        """
        Enregistre l'alerte localement/directement dans MongoDB (Mode Mongo)
        et déclenche la notification temps réel vers l'API.
        """
        if not MONGO_OK or not self.db:
            return

        try:
            col = self.db["monitor_alerts"]
            alert_doc = {
                "anomaly_type": anomaly_type,
                "detail": detail,
                "severity": severity,
                "agent_hostname": self.hostname,
                "detection_time": datetime.utcnow(), # Objet datetime local
                **kwargs
            }
            
            # Sauvegarde dans MongoDB
            res = col.insert_one(alert_doc)
            
            # Injecter l'ID généré par Mongo dans le dictionnaire pour le broadcast
            alert_doc["_id"] = res.inserted_id
            
            if self.verbose:
                print(f"[+] Alerte enregistrée en DB : {anomaly_type}")

            # POSITIONNEMENT DU BROADCAST : Juste ici !
            self._broadcast(alert_doc)

        except Exception as e:
            print(f"[!] Erreur lors de la sauvegarde de l'alerte : {e}")

    #  helpers

    def _lite(self, metrics: dict) -> dict:
        """Version allégée des métriques pour le broadcast SSE."""
        lite = {k: v for k, v in metrics.items() if k != "processes"}
        lite["top_processes"] = sorted(
            metrics.get("processes", []),
            key=lambda p: p.get("cpu_pct", 0), reverse=True
        )[:5]
        return lite

    def _post(self, path: str, payload: dict):
        """POST silencieux vers le backend — ne bloque pas si le backend est down."""
        if not self._session:
            return
        try:
            self._session.post(
                f"{self._api_base}{path}",
                json=payload,
                timeout=3,
            )
        except Exception:
            pass


#Backend API

class ApiBackend:
    """Mode production : tout passe par /api/monitoring/push."""

    def __init__(self, api_url: str, token: str):
        if not REQUESTS_OK:
            print("[!] requests manquant — pip install requests")
            sys.exit(1)
        self._url     = f"{api_url.rstrip('/')}/api/monitoring/push"
        self._session = requests.Session()
        self._session.headers.update({
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token}",
        })

    def save_metrics(self, metrics: dict):
        for attempt in range(1, MAX_RETRIES + 1):
            try:
                r = self._session.post(self._url, json=metrics, timeout=10)
                if r.status_code == 200:
                    return
                print(f"[!] API push échoué — HTTP {r.status_code}")
                return
            except requests.exceptions.ConnectionError:
                print(f"[!] Connexion refusée (tentative {attempt}/{MAX_RETRIES})")
            except Exception as e:
                print(f"[!] Erreur push : {e}")
                return
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_DELAY)

    def save_alerts(self, alerts: list[dict]):
        for a in alerts:
            print(f"[ALERT] {a.get('anomaly_type')} — {a.get('detail','')[:80]}")


#Agent principal

class Agent:

    def __init__(self, backend, interval: int, verbose: bool = False,
                 enable_filewatcher: bool = True):
        self.collector     = MetricsCollector()
        self.analyser      = LocalAnalyser()
        self.proc_watchdog = ProcessWatchdog()
        self.file_watchdog = FileWatchdog(self.collector.os_type) if enable_filewatcher else None
        self.backend       = backend
        self.interval      = interval
        self.verbose       = verbose
        self._tick_count   = 0

    def start(self):
        print(f"[*] Agent IDS démarré")
        print(f"    Hôte        : {self.collector.hostname} ({self.collector.os_type})")
        print(f"    IP main     : {self.collector._net_ips['main']}")
        print(f"    Intervalle  : {self.interval}s")
        print(f"    FileWatcher : {'activé' if self.file_watchdog else 'désactivé'}")
        print(f"    Ctrl+C pour arrêter\n")
        self._tick()
        try:
            while True:
                time.sleep(self.interval)
                self._tick()
        except KeyboardInterrupt:
            print("\n[*] Arrêt de l'agent.")

    def _tick(self):
        try:
            self._tick_count += 1
            metrics = self.collector.collect()
            if self._tick_count % 120 == 0:
                self.collector.refresh_ips()

            if self.verbose:
                suspects  = sum(1 for p in metrics["processes"] if p["suspicious"])
                overloads = sum(1 for p in metrics["processes"]
                                if p.get("cpu_pct", 0) >= THRESHOLDS["proc_cpu_critical"])
                print(f"[{time.strftime('%H:%M:%S')}] "
                      f"IP={metrics['ip_main']}  "
                      f"CPU={metrics['cpu_pct']:5.1f}%  "
                      f"RAM={metrics['ram_pct']:5.1f}%  "
                      f"DISK={metrics['disk_pct']:5.1f}%  "
                      f"CONNS={metrics['open_connections']:3d}  "
                      f"PROCS={metrics['process_count']:3d}  "
                      f"SUSPECTS={suspects}  OVERLOADS={overloads}")

            overloaded      = self.proc_watchdog.check(metrics["processes"])
            overloaded_pids = {p["pid"] for p in overloaded}
            for proc in metrics["processes"]:
                if proc.get("pid") in overloaded_pids:
                    proc["overloaded"] = True

            file_changes = self.file_watchdog.check() if self.file_watchdog else []

            self.backend.save_metrics(metrics)

            alerts = self.analyser.analyse(metrics, file_changes, overloaded)
            if alerts:
                self.backend.save_alerts(alerts)

        except Exception as e:
            print(f"[!] Erreur tick : {e}")


# Point d'entrée 

def parse_args():
    parser = argparse.ArgumentParser(description="Agent de monitoring IDS")
    parser.add_argument("--mode",           choices=["mongo", "api"], default="mongo")
    parser.add_argument("--mongo",          default=os.environ.get("IDS_MONGO_URI",   DEFAULT_MONGO_URI))
    parser.add_argument("--api",            default=os.environ.get("IDS_API_URL",     DEFAULT_API_URL))
    parser.add_argument("--token",          default=os.environ.get("IDS_AGENT_TOKEN", DEFAULT_TOKEN))
    parser.add_argument("--db",             default=DEFAULT_DB)
    parser.add_argument("--interval",       type=int, default=int(os.environ.get("IDS_INTERVAL", DEFAULT_INTERVAL)))
    parser.add_argument("--no-filewatcher", action="store_true")
    parser.add_argument("--verbose", "-v",  action="store_true")
    return parser.parse_args()


if __name__ == "__main__":
    args = parse_args()
    if args.mode == "mongo":
        backend = MongoBackend(
            uri     = args.mongo,
            db_name = args.db,
            api_url = args.api,
            token   = args.token,
        )
    else:
        backend = ApiBackend(api_url=args.api, token=args.token)

    Agent(
        backend            = backend,
        interval           = args.interval,
        verbose            = args.verbose,
        enable_filewatcher = not args.no_filewatcher,
    ).start()