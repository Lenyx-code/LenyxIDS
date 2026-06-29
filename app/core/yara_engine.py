"""
core/yara_engine.py — Moteur d'analyse YARA
Fonctionne sans internet grâce aux règles embarquées.
Télécharge les règles communautaires si une connexion est disponible.
"""
import os
import re
import time
import hashlib
import zipfile
import shutil
import threading
import yara

try:
    import requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

RULES_DIR       = "storage/yara/rules"
COMPILED_PATH   = "storage/yara/compiled.yarc"
BUILTIN_DIR     = "storage/yara/builtin"
RULES_ZIP_URL   = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
RULES_ZIP_PATH  = "storage/yara/rules_master.zip"
RULES_EXTRACT   = "storage/yara/raw"
UPDATE_INTERVAL = 86400  # 24h

INCLUDED_CATEGORIES = {
    "malware", "exploit_kits", "webshells",
    "antidebug_antivm", "crypto", "CVE_Rules", "packers",
}
RULE_EXTENSIONS = {".yar", ".yara"}

_lock           = threading.Lock()
_compiled_rules = None
_rules_source   = "none"   # "builtin" | "community" | "none"

# Règles embarquées — fonctionnent SANS internet
# Couvrent les patterns les plus communs et universels

BUILTIN_RULES = {

"webshells.yar": r"""
rule PHP_Webshell_Generic {
    meta:
        description = "Détecte les webshells PHP génériques"
        severity    = "critical"
    strings:
        $eval1  = "eval(base64_decode(" nocase
        $eval2  = "eval(gzinflate(" nocase
        $eval3  = "eval(str_rot13(" nocase
        $cmd1   = "$_POST['cmd']" nocase
        $cmd2   = "$_REQUEST['cmd']" nocase
        $cmd3   = "system($_GET" nocase
        $cmd4   = "passthru($_POST" nocase
        $shell1 = "shell_exec($_" nocase
        $shell2 = "preg_replace('/.*/e'" nocase
        $shell3 = "assert($_POST" nocase
    condition:
        any of them
}

rule Python_Reverse_Shell {
    meta:
        description = "Détecte un reverse shell Python"
        severity    = "critical"
    strings:
        $s1 = "import socket,subprocess,os" nocase
        $s2 = "socket.AF_INET,socket.SOCK_STREAM" nocase
        $s3 = "pty.spawn" nocase
        $s4 = "os.dup2(s.fileno()" nocase
        $s5 = "/bin/sh" nocase
        $s6 = "connect(('" nocase
    condition:
        2 of them
}

rule Bash_Reverse_Shell {
    meta:
        description = "Détecte un reverse shell Bash"
        severity    = "critical"
    strings:
        $s1 = "/dev/tcp/" nocase
        $s2 = "bash -i" nocase
        $s3 = "0>&1" nocase
        $s4 = "nc -e /bin/bash" nocase
        $s5 = "nc -e /bin/sh" nocase
        $s6 = "ncat -e" nocase
    condition:
        any of them
}
""",

"ransomware.yar": r"""
rule Ransomware_Generic_Indicators {
    meta:
        description = "Détecte des indicateurs génériques de ransomware"
        severity    = "critical"
    strings:
        $r1 = "Your files have been encrypted" nocase
        $r2 = "All your files are encrypted" nocase
        $r3 = "send Bitcoin" nocase
        $r4 = "pay ransom" nocase
        $r5 = "decrypt your files" nocase
        $r6 = "YOUR_FILES_ARE_ENCRYPTED" nocase
        $r7 = "HOW_TO_RECOVER" nocase
        $r8 = "CryptoLocker" nocase
        $r9 = ".onion" nocase
        $ext1 = ".locked"
        $ext2 = ".encrypted"
        $ext3 = ".crypted"
        $ext4 = ".crypt"
    condition:
        2 of ($r*) or 2 of ($ext*)
}

rule Ransomware_File_Extension_Mass_Rename {
    meta:
        description = "Détecte des appels massifs de renommage fichiers"
        severity    = "high"
    strings:
        $s1 = "MoveFileEx" nocase
        $s2 = "CryptEncrypt" nocase
        $s3 = "CryptAcquireContext" nocase
        $s4 = "DeleteShadowCopies" nocase
        $s5 = "vssadmin delete shadows" nocase
        $s6 = "bcdedit /set {default} recoveryenabled No" nocase
    condition:
        2 of them
}
""",

"malware_generic.yar": r"""
rule Suspicious_PowerShell_Encoded {
    meta:
        description = "Détecte du PowerShell encodé suspect"
        severity    = "high"
    strings:
        $s1 = "powershell -enc" nocase
        $s2 = "powershell -EncodedCommand" nocase
        $s3 = "powershell -e " nocase
        $s4 = "IEX(New-Object" nocase
        $s5 = "Invoke-Expression" nocase
        $s6 = "DownloadString(" nocase
        $s7 = "FromBase64String(" nocase
        $s8 = "-nop -w hidden" nocase
        $s9 = "bypass -noprofile" nocase
    condition:
        2 of them
}

rule Suspicious_Base64_Executable {
    meta:
        description = "Détecte un exécutable encodé en base64"
        severity    = "high"
    strings:
        $mz_b64_1 = "TVqQAAMAAAAEAAAA" // MZ header en base64
        $mz_b64_2 = "TVpAAA"
        $mz_b64_3 = "TVoA"
        $decode1   = "base64_decode" nocase
        $decode2   = "FromBase64String" nocase
        $decode3   = "base64 -d" nocase
    condition:
        any of ($mz_b64*) or
        (any of ($decode*) and filesize < 500KB)
}

rule Keylogger_Indicators {
    meta:
        description = "Détecte des indicateurs de keylogger"
        severity    = "high"
    strings:
        $k1 = "SetWindowsHookEx" nocase
        $k2 = "GetAsyncKeyState" nocase
        $k3 = "GetKeyState" nocase
        $k4 = "keylogger" nocase
        $k5 = "keystroke" nocase
        $k6 = "WH_KEYBOARD_LL" nocase
    condition:
        2 of them
}

rule Suspicious_Network_Connection {
    meta:
        description = "Connexion réseau suspecte vers C2"
        severity    = "medium"
    strings:
        $s1 = "InternetOpenUrl" nocase
        $s2 = "HttpSendRequest" nocase
        $s3 = "WSAStartup" nocase
        $s4 = "connect(" nocase
        $c2_1 = "pastebin.com" nocase
        $c2_2 = "raw.githubusercontent.com" nocase
        $c2_3 = "bit.ly" nocase
        $c2_4 = "ngrok.io" nocase
    condition:
        any of ($s*) and any of ($c2_*)
}

rule Privilege_Escalation_Linux {
    meta:
        description = "Tentative d'escalade de privilèges Linux"
        severity    = "critical"
    strings:
        $s1 = "chmod +s" nocase
        $s2 = "chmod 4777" nocase
        $s3 = "SUID" nocase
        $s4 = "setuid(0)" nocase
        $s5 = "setgid(0)" nocase
        $s6 = "/etc/sudoers" nocase
        $s7 = "sudo -l" nocase
        $s8 = "pkexec" nocase
    condition:
        2 of them
}

rule Credential_Harvesting {
    meta:
        description = "Détecte la collecte de credentials"
        severity    = "high"
    strings:
        $s1 = "/etc/shadow" nocase
        $s2 = "/etc/passwd" nocase
        $s3 = "SAM database" nocase
        $s4 = "lsass.exe" nocase
        $s5 = "mimikatz" nocase
        $s6 = "sekurlsa" nocase
        $s7 = "hashdump" nocase
        $s8 = "ntds.dit" nocase
        $s9 = "LaZagne" nocase
    condition:
        any of them
}
""",

"suspicious_scripts.yar": r"""
rule Miner_Cryptominer {
    meta:
        description = "Détecte un cryptominer"
        severity    = "high"
    strings:
        $s1 = "stratum+tcp://" nocase
        $s2 = "xmrig" nocase
        $s3 = "monero" nocase
        $s4 = "mining pool" nocase
        $s5 = "hashrate" nocase
        $s6 = "coinhive" nocase
        $s7 = "cryptonight" nocase
    condition:
        2 of them
}

rule Suspicious_Archive_Dropper {
    meta:
        description = "Archive qui extrait et exécute un fichier"
        severity    = "medium"
    strings:
        $s1 = "WScript.Shell" nocase
        $s2 = "Shell.Application" nocase
        $s3 = "CreateObject" nocase
        $exec1 = ".Run(" nocase
        $exec2 = ".ShellExecute(" nocase
        $exec3 = ".Exec(" nocase
    condition:
        any of ($s*) and any of ($exec*)
}

rule SQL_Injection_Payload {
    meta:
        description = "Payload SQL Injection dans un fichier"
        severity    = "medium"
    strings:
        $s1 = "' OR '1'='1" nocase
        $s2 = "'; DROP TABLE" nocase
        $s3 = "UNION SELECT" nocase
        $s4 = "1=1--" nocase
        $s5 = "admin'--" nocase
        $s6 = "SLEEP(5)--" nocase
        $s7 = "BENCHMARK(" nocase
    condition:
        2 of them
}
""",

}


# Gestion des règles embarquées

def _write_builtin_rules():
    """Écrit les règles embarquées sur disque si elles n'existent pas."""
    os.makedirs(BUILTIN_DIR, exist_ok=True)
    written = 0
    for filename, content in BUILTIN_RULES.items():
        path = os.path.join(BUILTIN_DIR, filename)
        if not os.path.exists(path):
            with open(path, "w") as f:
                f.write(content)
            written += 1
    if written:
        print(f"[+] YARA : {written} fichiers de règles embarquées écrits dans {BUILTIN_DIR}")


def _compile_builtin() -> bool:
    """Compile uniquement les règles embarquées."""
    global _rules_source
    _write_builtin_rules()

    rule_files = {}
    for fname in os.listdir(BUILTIN_DIR):
        if os.path.splitext(fname)[1] in RULE_EXTENSIONS:
            ns = fname.replace(".", "_")
            rule_files[ns] = os.path.join(BUILTIN_DIR, fname)

    if not rule_files:
        return False

    try:
        compiled = yara.compile(filepaths=rule_files)
        compiled.save(COMPILED_PATH)
        _rules_source = "builtin"
        print(f"[+] YARA : règles embarquées compilées ({len(rule_files)} fichiers)")
        return True
    except yara.SyntaxError as e:
        print(f"[!] YARA : erreur règles embarquées — {e}")
        return False


# Téléchargement des règles communautaires 

def _has_internet(timeout: int = 5) -> bool:
    if not REQUESTS_AVAILABLE:
        return False
    try:
        requests.get("https://github.com", timeout=timeout)
        return True
    except Exception:
        return False


def _download_rules() -> bool:
    if not REQUESTS_AVAILABLE:
        print("[!] YARA : module requests non disponible")
        return False
    print("[*] YARA : téléchargement des règles communautaires...")
    try:
        resp = requests.get(RULES_ZIP_URL, stream=True, timeout=120)
        resp.raise_for_status()
        os.makedirs(os.path.dirname(RULES_ZIP_PATH), exist_ok=True)
        with open(RULES_ZIP_PATH, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                f.write(chunk)
        print(f"[+] YARA : téléchargé ({os.path.getsize(RULES_ZIP_PATH)//1024} KB)")
        return True
    except Exception as e:
        print(f"[!] YARA : téléchargement échoué — {e}")
        return False


def _extract_and_compile_community() -> bool:
    global _rules_source
    print("[*] YARA : extraction des règles communautaires...")

    if os.path.exists(RULES_EXTRACT):
        shutil.rmtree(RULES_EXTRACT)
    os.makedirs(RULES_EXTRACT, exist_ok=True)

    try:
        with zipfile.ZipFile(RULES_ZIP_PATH, "r") as z:
            for member in z.namelist():
                parts = member.split("/")
                if len(parts) < 2:
                    continue
                category = parts[1]
                if category not in INCLUDED_CATEGORIES:
                    continue
                _, ext = os.path.splitext(member)
                if ext not in RULE_EXTENSIONS:
                    continue
                target_dir  = os.path.join(RULES_EXTRACT, category)
                os.makedirs(target_dir, exist_ok=True)
                fname       = os.path.basename(member)
                target_path = os.path.join(target_dir, fname)
                with z.open(member) as src, open(target_path, "wb") as dst:
                    dst.write(src.read())
    except zipfile.BadZipFile as e:
        print(f"[!] YARA : ZIP corrompu — {e}")
        return False

    # Compiler communautaires + embarquées ensemble
    rule_files = {}

    # Embarquées en priorité
    _write_builtin_rules()
    for fname in os.listdir(BUILTIN_DIR):
        if os.path.splitext(fname)[1] in RULE_EXTENSIONS:
            ns = "builtin_" + fname.replace(".", "_")
            rule_files[ns] = os.path.join(BUILTIN_DIR, fname)

    # Communautaires
    skipped = 0
    for root, _, files in os.walk(RULES_EXTRACT):
        for fname in files:
            if os.path.splitext(fname)[1] not in RULE_EXTENSIONS:
                continue
            fpath   = os.path.join(root, fname)
            content = _sanitize_rule_file(fpath)
            if content is None:
                skipped += 1
                continue
            ns = fpath.replace(RULES_EXTRACT, "").strip("/\\") \
                      .replace("/", "_").replace("\\", "_")
            rule_files[ns] = fpath

    print(f"[*] YARA : {len(rule_files)} règles à compiler ({skipped} ignorées)...")

    try:
        compiled = yara.compile(filepaths=rule_files)
        compiled.save(COMPILED_PATH)
        _rules_source = "community"
        print(f"[+] YARA : {len(rule_files)} règles communautaires + embarquées compilées")
        return True
    except yara.SyntaxError:
        return _compile_individually(rule_files)


def _compile_individually(rule_files: dict) -> bool:
    global _rules_source
    print("[*] YARA : compilation individuelle (mode dégradé)...")
    valid = {}
    for ns, path in rule_files.items():
        try:
            yara.compile(filepath=path)
            valid[ns] = path
        except yara.SyntaxError:
            pass
    if not valid:
        return False
    try:
        compiled = yara.compile(filepaths=valid)
        compiled.save(COMPILED_PATH)
        _rules_source = "community"
        print(f"[+] YARA : {len(valid)} règles compilées (mode individuel)")
        return True
    except Exception as e:
        print(f"[!] YARA : échec compilation individuelle — {e}")
        return False


def _sanitize_rule_file(path: str) -> str | None:
    try:
        with open(path, "r", errors="replace") as f:
            content = f.read()
        for imp in ["import \"magic\"", "import \"hash\"",
                    "import \"math\"", "import \"dotnet\""]:
            if imp in content:
                return None
        content = re.sub(r'include\s+"[^"]*"', "", content)
        return content
    except Exception:
        return None


# Initialisation principale

def _ensure_dirs():
    for d in [RULES_DIR, BUILTIN_DIR, os.path.dirname(COMPILED_PATH)]:
        os.makedirs(d, exist_ok=True)


def _load_compiled() -> bool:
    global _compiled_rules
    try:
        with _lock:
            _compiled_rules = yara.load(COMPILED_PATH)
        print(f"[+] YARA : règles chargées en mémoire (source: {_rules_source})")
        return True
    except Exception as e:
        print(f"[!] YARA : échec chargement — {e}")
        return False


def update_rules(force: bool = False) -> bool:
    """
    Stratégie de chargement :
    1. Si règles compilées récentes et pas force → charger le cache
    2. Si internet disponible → télécharger communautaires + embarquées
    3. Sinon → compiler uniquement les règles embarquées
    """
    global _rules_source
    _ensure_dirs()

    compiled_fresh = (
        os.path.exists(COMPILED_PATH)
        and (time.time() - os.path.getmtime(COMPILED_PATH)) < UPDATE_INTERVAL
    )

    if compiled_fresh and not force:
        print("[*] YARA : cache valide, chargement...")
        return _load_compiled()

    if _has_internet():
        print("[*] YARA : connexion internet détectée — téléchargement des règles communautaires")
        if _download_rules() and _extract_and_compile_community():
            return _load_compiled()
        print("[!] YARA : téléchargement/compilation échoué — fallback sur règles embarquées")
    else:
        print("[!] YARA : pas de connexion internet — utilisation des règles embarquées")

    # Fallback : règles embarquées
    if _compile_builtin():
        return _load_compiled()

    print("[!!!] YARA : impossible de charger des règles — moteur désactivé")
    return False


# Analyse de fichier

def get_engine_status() -> dict:
    return {
        "ready":        _compiled_rules is not None,
        "rules_source": _rules_source,
        "compiled_path_exists": os.path.exists(COMPILED_PATH),
    }


def _sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _severity_from_matches(matches: list) -> str:
    tags_all = []
    for m in matches:
        tags_all.extend([t.lower() for t in m.tags])
        meta = m.meta or {}
        sev  = str(meta.get("severity", "")).lower()
        if sev:
            tags_all.append(sev)
    if any(t in tags_all for t in ["critical", "ransomware", "rootkit", "backdoor"]):
        return "critical"
    if any(t in tags_all for t in ["high", "trojan", "rat", "exploit", "webshell"]):
        return "high"
    if any(t in tags_all for t in ["medium", "packer", "suspicious", "miner"]):
        return "medium"
    return "low"


def analyze_file(file_path: str, original_name: str = "") -> dict:
    global _compiled_rules

    if _compiled_rules is None:
        return {
            "status":  "error",
            "message": "Moteur YARA non initialisé",
            "rules_source": _rules_source,
        }

    if not os.path.exists(file_path):
        return {"status": "error", "message": "Fichier introuvable"}

    file_size = os.path.getsize(file_path)
    sha256    = _sha256_file(file_path)

    try:
        with _lock:
            matches = _compiled_rules.match(file_path, timeout=30)
    except yara.TimeoutError:
        return {
            "status":       "error",
            "message":      "Timeout — fichier trop complexe (>30s)",
            "file_name":    original_name,
            "sha256":       sha256,
            "file_size_kb": round(file_size / 1024, 2),
            "rules_source": _rules_source,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}

    is_malicious = len(matches) > 0
    severity     = _severity_from_matches(matches) if is_malicious else "none"

    match_details = []
    for m in matches:
        match_details.append({
            "rule":      m.rule,
            "namespace": m.namespace,
            "tags":      list(m.tags),
            "meta":      dict(m.meta) if m.meta else {},
            "strings": [
                {
                    "identifier": s.identifier,
                    "data": repr(s.instances[0].matched_data[:64]) if s.instances else "",
                }
                for s in m.strings[:5]
            ],
        })

    categories = list({
        m.namespace.split("_")[0]
        for m in matches
        if "_" in m.namespace
    })

    return {
        "status":        "malicious" if is_malicious else "clean",
        "is_malicious":  is_malicious,
        "severity":      severity,
        "file_name":     original_name or os.path.basename(file_path),
        "file_size_kb":  round(file_size / 1024, 2),
        "sha256":        sha256,
        "rules_matched": len(matches),
        "categories":    categories,
        "matches":       match_details,
        "rules_source":  _rules_source,   # "builtin" ou "community"
        "scanned_at":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


# Auto-update en background

def start_auto_update():
    def _worker():
        update_rules()
        while True:
            time.sleep(UPDATE_INTERVAL)
            update_rules()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    print("[*] YARA : auto-update activé (toutes les 24h)")