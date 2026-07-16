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

try:
    import rarfile
    RARFILE_AVAILABLE = True
except ImportError:
    RARFILE_AVAILABLE = False

try:
    import py7zr
    PY7ZR_AVAILABLE = True
except ImportError:
    PY7ZR_AVAILABLE = False

RULES_DIR       = "storage/yara/rules"
COMPILED_PATH   = "storage/yara/compiled.yarc"
BUILTIN_DIR     = "storage/yara/builtin"
RULES_ZIP_URL   = "https://github.com/Yara-Rules/rules/archive/refs/heads/master.zip"
RULES_ZIP_PATH  = "storage/yara/rules_master.zip"
RULES_EXTRACT   = "storage/yara/raw"
UPDATE_INTERVAL = 86400  # 24h

# --- Scan récursif d'archives (protection anti zip-bomb / zip-slip) ---
ARCHIVE_SCRATCH_DIR       = "storage/yara/archive_scratch"
MAX_ARCHIVE_DEPTH         = 5            # profondeur max d'archives imbriquées (zip dans zip dans zip...)
MAX_FILES_PER_ARCHIVE     = 2000         # nb max de fichiers extraits par archive
MAX_TOTAL_EXTRACTED_BYTES = 500 * 1024 * 1024   # 500 Mo au total extraits par archive analysée
MAX_SINGLE_FILE_BYTES     = 200 * 1024 * 1024   # 200 Mo max pour un seul fichier extrait
MAX_COMPRESSION_RATIO     = 100          # ratio décompressé/compressé au-delà duquel on suspecte une zip-bomb
ARCHIVE_MAGIC_ZIP         = b"PK\x03\x04"
ARCHIVE_MAGIC_RAR4        = b"Rar!\x1a\x07\x00"
ARCHIVE_MAGIC_RAR5        = b"Rar!\x1a\x07\x01\x00"
ARCHIVE_MAGIC_7Z          = b"7z\xbc\xaf\x27\x1c"
SUPPORTED_ARCHIVE_TYPES   = {"zip", "rar", "7z"}

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

# ------------------------------------------------------------------
# NOUVEAU : exécutables Windows (PE / .exe / .dll)
# ------------------------------------------------------------------
"executables_pe.yar": r"""
rule PE_File_Generic {
    meta:
        description = "Identifie un exécutable PE (Windows)"
        severity    = "info"
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule PE_Packer_Suspicious_Sections {
    meta:
        description = "Sections PE typiques de packers connus (UPX, ASPack, Themida, MPRESS...)"
        severity    = "medium"
    strings:
        $upx1 = "UPX0" nocase
        $upx2 = "UPX1" nocase
        $upx3 = "UPX!" nocase
        $asp1 = ".aspack" nocase
        $asp2 = ".adata" nocase
        $mpr1 = "MPRESS1" nocase
        $mpr2 = "MPRESS2" nocase
        $thm1 = ".themida" nocase
        $thm2 = "Themida" nocase
        $vmp1 = ".vmp0" nocase
        $vmp2 = ".vmp1" nocase
    condition:
        uint16(0) == 0x5A4D and any of them
}

rule PE_Suspicious_Imports_Injection {
    meta:
        description = "Combinaisons d'API typiques d'injection de code / process hollowing"
        severity    = "critical"
    strings:
        $a1 = "VirtualAllocEx" nocase
        $a2 = "WriteProcessMemory" nocase
        $a3 = "CreateRemoteThread" nocase
        $a4 = "NtUnmapViewOfSection" nocase
        $a5 = "SetThreadContext" nocase
        $a6 = "ResumeThread" nocase
        $a7 = "QueueUserAPC" nocase
    condition:
        uint16(0) == 0x5A4D and 3 of them
}

rule PE_Suspicious_AntiDebug {
    meta:
        description = "Techniques anti-debug / anti-VM courantes dans un PE"
        severity    = "medium"
    strings:
        $d1 = "IsDebuggerPresent" nocase
        $d2 = "CheckRemoteDebuggerPresent" nocase
        $d3 = "NtQueryInformationProcess" nocase
        $d4 = "OutputDebugString" nocase
        $v1 = "VMware" nocase
        $v2 = "VBoxService" nocase
        $v3 = "VirtualBox" nocase
        $v4 = "SbieDll.dll" nocase
    condition:
        uint16(0) == 0x5A4D and (2 of ($d*) or any of ($v*))
}

rule PE_Dropper_Embedded_PE {
    meta:
        description = "Un PE qui contient un autre en-tête MZ embarqué (dropper)"
        severity    = "high"
    strings:
        $mz = "MZ"
    condition:
        uint16(0) == 0x5A4D and #mz > 3
}

rule PE_Suspicious_No_Signature_Small {
    meta:
        description = "Petit PE sans section .rsrc/.reloc typique, souvent stub malveillant"
        severity    = "low"
    condition:
        uint16(0) == 0x5A4D and filesize < 50KB and filesize > 512
}
""",

# ------------------------------------------------------------------
# NOUVEAU : exécutables Linux (ELF)
# ------------------------------------------------------------------
"executables_elf.yar": r"""
rule ELF_File_Generic {
    meta:
        description = "Identifie un exécutable ELF (Linux)"
        severity    = "info"
    condition:
        uint32(0) == 0x464C457F
}

rule ELF_Reverse_Shell_Strings {
    meta:
        description = "Chaînes de reverse shell dans un binaire ELF"
        severity    = "critical"
    strings:
        $s1 = "/bin/sh"
        $s2 = "/bin/bash"
        $s3 = "socket"
        $s4 = "connect"
        $s5 = "dup2"
        $s6 = "execve"
    condition:
        uint32(0) == 0x464C457F and 4 of them
}

rule ELF_LD_Preload_Hijack {
    meta:
        description = "Indicateurs de détournement via LD_PRELOAD (rootkit userland)"
        severity    = "critical"
    strings:
        $s1 = "LD_PRELOAD" nocase
        $s2 = "/etc/ld.so.preload" nocase
        $s3 = "dlopen" nocase
        $s4 = "dlsym" nocase
    condition:
        uint32(0) == 0x464C457F and 2 of them
}

rule ELF_Suspicious_Persistence {
    meta:
        description = "Techniques de persistance courantes (cron, systemd, bashrc)"
        severity    = "high"
    strings:
        $s1 = "/etc/cron" nocase
        $s2 = "/etc/init.d" nocase
        $s3 = "/etc/systemd/system" nocase
        $s4 = ".bashrc" nocase
        $s5 = ".bash_profile" nocase
        $s6 = "crontab -l" nocase
    condition:
        uint32(0) == 0x464C457F and 2 of them
}

rule ELF_Statically_Linked_Busybox_Style {
    meta:
        description = "ELF statique embarquant plusieurs utilitaires (typique de botnets IoT type Mirai)"
        severity    = "high"
    strings:
        $s1 = "busybox" nocase
        $s2 = "/proc/net/tcp"
        $s3 = "watchdog" nocase
        $s4 = "telnet" nocase
        $s5 = "DDOS" nocase
        $s6 = "SYN" 
    condition:
        uint32(0) == 0x464C457F and 3 of them
}
""",

# ------------------------------------------------------------------
# NOUVEAU : archives (ZIP / RAR / 7z / auto-extractibles)
# ------------------------------------------------------------------
"archives_suspicious.yar": r"""
rule Archive_ZIP_Generic {
    meta:
        description = "Identifie une archive ZIP"
        severity    = "info"
    condition:
        uint32(0) == 0x04034b50
}

rule Archive_RAR_Generic {
    meta:
        description = "Identifie une archive RAR"
        severity    = "info"
    condition:
        uint32(0) == 0x21726152
}

rule Archive_SevenZip_Generic {
    meta:
        description = "Identifie une archive 7z"
        severity    = "info"
    condition:
        uint32(0) == 0x27afbc37
}

rule Archive_Double_Extension_Filename {
    meta:
        description = "Nom de fichier interne à double extension (ex: facture.pdf.exe)"
        severity    = "high"
    strings:
        $e1 = ".pdf.exe" nocase
        $e2 = ".doc.exe" nocase
        $e3 = ".docx.exe" nocase
        $e4 = ".xls.exe" nocase
        $e5 = ".jpg.exe" nocase
        $e6 = ".jpg.scr" nocase
        $e7 = ".txt.exe" nocase
        $e8 = ".pdf.scr" nocase
        $e9 = ".zip.exe" nocase
    condition:
        any of them
}

rule Archive_Self_Extracting_SFX {
    meta:
        description = "Archive auto-extractible (SFX) qui exécute automatiquement un binaire"
        severity    = "medium"
    strings:
        $s1 = "WinRAR SFX" nocase
        $s2 = "Setup=" nocase
        $s3 = "Silent=1" nocase
        $s4 = "RunProgram=" nocase
        $s5 = "7-Zip Self-Extracting" nocase
    condition:
        any of them
}

rule Archive_Contains_Script_Payload {
    meta:
        description = "Archive contenant un script d'exécution (bat/vbs/js/ps1/wsf) — typique de phishing"
        severity    = "medium"
    strings:
        $n1 = ".bat" nocase
        $n2 = ".vbs" nocase
        $n3 = ".js" nocase
        $n4 = ".wsf" nocase
        $n5 = ".ps1" nocase
        $n6 = ".hta" nocase
        $n7 = ".lnk" nocase
    condition:
        (uint32(0) == 0x04034b50 or uint32(0) == 0x21726152 or uint32(0) == 0x27afbc37)
        and any of them
}
""",

# ------------------------------------------------------------------
# NOUVEAU : documents Office avec macros
# ------------------------------------------------------------------
"office_macro.yar": r"""
rule Office_OLE_Generic {
    meta:
        description = "Identifie un document Office ancien format (OLE2 - .doc/.xls/.ppt)"
        severity    = "info"
    condition:
        uint32(0) == 0xE011CFD0 or uint32(0) == 0xE011CFD0
}

rule Office_OOXML_Generic {
    meta:
        description = "Identifie un document Office moderne (docx/xlsx/pptx = ZIP)"
        severity    = "info"
    condition:
        uint32(0) == 0x04034b50
}

rule Office_Macro_AutoExec {
    meta:
        description = "Macro VBA avec exécution automatique à l'ouverture"
        severity    = "high"
    strings:
        $a1 = "AutoOpen" nocase
        $a2 = "AutoExec" nocase
        $a3 = "Document_Open" nocase
        $a4 = "Workbook_Open" nocase
        $a5 = "AutoClose" nocase
    condition:
        any of them
}

rule Office_Macro_Shell_Execution {
    meta:
        description = "Macro VBA qui lance un shell / PowerShell / téléchargement"
        severity    = "critical"
    strings:
        $s1 = "Shell(" nocase
        $s2 = "WScript.Shell" nocase
        $s3 = "CreateObject(\"WScript.Shell\")" nocase
        $s4 = "powershell" nocase
        $s5 = "cmd.exe /c" nocase
        $s6 = "URLDownloadToFile" nocase
        $s7 = "MSXML2.XMLHTTP" nocase
    condition:
        2 of them
}

rule Office_Macro_Obfuscation {
    meta:
        description = "Obfuscation typique de macros malveillantes (Chr/StrReverse concaténés)"
        severity    = "medium"
    strings:
        $o1 = "Chr(" nocase
        $o2 = "StrReverse(" nocase
        $o3 = "Xor" nocase
        $o4 = "& Chr(" nocase
    condition:
        2 of them
}
""",

# ------------------------------------------------------------------
# NOUVEAU : scripts shell / batch étendus
# ------------------------------------------------------------------
"scripts_shell_extended.yar": r"""
rule Shell_Pipe_To_Interpreter {
    meta:
        description = "Téléchargement puis exécution directe via pipe (curl|bash, wget|sh...)"
        severity    = "critical"
    strings:
        $s1 = "curl -s" nocase
        $s2 = "curl -k" nocase
        $s3 = "wget -q" nocase
        $s4 = "| bash" nocase
        $s5 = "| sh" nocase
        $s6 = "|bash" nocase
        $s7 = "|sh" nocase
        $s8 = "bash <(curl" nocase
    condition:
        (any of ($s1,$s2,$s3,$s8)) and (any of ($s4,$s5,$s6,$s7))
}

rule Shell_Firewall_Tampering {
    meta:
        description = "Modification suspecte du pare-feu ou des règles réseau"
        severity    = "high"
    strings:
        $s1 = "iptables -F" nocase
        $s2 = "iptables --flush" nocase
        $s3 = "ufw disable" nocase
        $s4 = "netsh advfirewall set allprofiles state off" nocase
    condition:
        any of them
}

rule Shell_Crontab_Persistence {
    meta:
        description = "Ajout de persistance via crontab / at"
        severity    = "high"
    strings:
        $s1 = "crontab -" nocase
        $s2 = "* * * * *"
        $s3 = "echo \"* " nocase
        $s4 = "/etc/cron.d/" nocase
    condition:
        any of them
}

rule Batch_Windows_Suspicious {
    meta:
        description = "Script .bat/.cmd Windows avec effacement de logs / désactivation defender"
        severity    = "critical"
    strings:
        $s1 = "wevtutil cl" nocase
        $s2 = "vssadmin delete shadows" nocase
        $s3 = "Set-MpPreference -DisableRealtimeMonitoring" nocase
        $s4 = "reg add" nocase
        $s5 = "schtasks /create" nocase
        $s6 = "netsh firewall" nocase
    condition:
        2 of them
}
""",

# ------------------------------------------------------------------
# NOUVEAU : JS / HTA / WSF (phishing, droppers)
# ------------------------------------------------------------------
"js_hta_suspicious.yar": r"""
rule JS_Heavy_Obfuscation {
    meta:
        description = "Obfuscation JavaScript lourde typique de droppers"
        severity    = "high"
    strings:
        $s1 = "eval(unescape(" nocase
        $s2 = "String.fromCharCode(" nocase
        $s3 = "document.write(unescape(" nocase
        $s4 = "eval(atob(" nocase
        $s5 = "new ActiveXObject" nocase
    condition:
        2 of them
}

rule HTA_WSF_Shell_Execution {
    meta:
        description = "Fichier HTA/WSF/JS qui instancie un Shell Windows"
        severity    = "critical"
    strings:
        $s1 = "WScript.Shell" nocase
        $s2 = "Shell.Application" nocase
        $s3 = ".Run(" nocase
        $s4 = "ActiveXObject(\"WScript.Shell\")" nocase
        $s5 = "mshta" nocase
    condition:
        any of ($s1,$s2,$s4) and any of ($s3,$s5)
}
""",

# ------------------------------------------------------------------
# NOUVEAU : raccourcis Windows (.lnk)
# ------------------------------------------------------------------
"lnk_suspicious.yar": r"""
rule LNK_File_Generic {
    meta:
        description = "Identifie un fichier raccourci Windows (.lnk)"
        severity    = "info"
    condition:
        uint32(0) == 0x0000004C
}

rule LNK_Suspicious_Target {
    meta:
        description = "Raccourci .lnk pointant vers un interpréteur de commandes"
        severity    = "high"
    strings:
        $s1 = "cmd.exe" nocase
        $s2 = "powershell.exe" nocase
        $s3 = "wscript.exe" nocase
        $s4 = "mshta.exe" nocase
        $s5 = "/c " nocase
        $s6 = "-enc " nocase
        $s7 = "-EncodedCommand" nocase
    condition:
        uint32(0) == 0x0000004C and 2 of them
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
        # Toujours réécrire pour garantir la synchro avec le code (mises à jour incluses)
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
    for d in [RULES_DIR, BUILTIN_DIR, os.path.dirname(COMPILED_PATH), ARCHIVE_SCRATCH_DIR]:
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


def init_engine(force_download: bool = True, timeout: int = 15) -> bool:
    """
    À appeler UNE FOIS au démarrage de l'outil, de façon bloquante.
    - Vérifie la connexion internet.
    - Si dispo : télécharge + compile immédiatement les règles communautaires
      et les stocke en local (storage/yara/compiled.yarc), pour que le moteur
      soit tout de suite prêt même hors-ligne aux lancements suivants.
    - Si pas de réseau ou échec : bascule sur les règles embarquées et les
      compile/charge quand même, pour ne jamais démarrer sans moteur.
    """
    global _rules_source
    _ensure_dirs()
    print("[*] YARA : initialisation du moteur au démarrage...")

    if force_download and _has_internet(timeout=timeout):
        print("[*] YARA : réseau détecté — téléchargement immédiat des règles (stockage local)")
        if _download_rules() and _extract_and_compile_community():
            ok = _load_compiled()
            if ok:
                print(f"[+] YARA : moteur prêt au démarrage (source: {_rules_source})")
            return ok
        print("[!] YARA : échec du téléchargement au démarrage — fallback règles embarquées")

    # Pas de réseau ou échec → on utilise/compile ce qu'on a déjà en local,
    # sinon on retombe sur les règles embarquées.
    return update_rules(force=False)


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


# Scan récursif des archives ZIP (zip-in-zip, zip bomb, zip slip, mdp)

def _detect_archive_type(file_path: str) -> str | None:
    """Détecte le type d'archive (zip/rar/7z) via sa signature binaire (magic bytes)."""
    try:
        with open(file_path, "rb") as f:
            head = f.read(8)
    except Exception:
        return None
    if head.startswith(ARCHIVE_MAGIC_ZIP):
        return "zip"
    if head.startswith(ARCHIVE_MAGIC_RAR5) or head.startswith(ARCHIVE_MAGIC_RAR4):
        return "rar"
    if head.startswith(ARCHIVE_MAGIC_7Z):
        return "7z"
    return None


def _is_zip_file(file_path: str) -> bool:
    # Conservé pour compatibilité, utilise désormais la détection générique
    return _detect_archive_type(file_path) == "zip"


def _safe_extract_path(base_dir: str, member_name: str) -> str | None:
    """
    Protection anti zip-slip : refuse tout chemin qui sortirait du
    dossier d'extraction (../../etc/passwd, chemin absolu, etc.).
    Retourne le chemin sûr, ou None si le membre est rejeté.
    """
    target = os.path.normpath(os.path.join(base_dir, member_name))
    base_dir_resolved = os.path.normpath(base_dir)
    if not (target == base_dir_resolved or target.startswith(base_dir_resolved + os.sep)):
        return None
    return target


def _zip_is_password_protected(zf: zipfile.ZipFile) -> bool:
    for info in zf.infolist():
        # bit 0 du flag_bits = entrée chiffrée
        if info.flag_bits & 0x1:
            return True
    return False


def _zip_compression_ratio(zf: zipfile.ZipFile) -> float:
    total_compressed   = sum(i.compress_size for i in zf.infolist()) or 1
    total_uncompressed = sum(i.file_size for i in zf.infolist())
    return total_uncompressed / total_compressed


def _extract_zip_safely(file_path: str, extract_to: str) -> dict:
    """
    Extrait un ZIP avec toutes les protections nécessaires.
    Retourne un rapport : {ok, warnings[], extracted_files[], password_protected, compression_ratio}
    """
    report = {
        "ok": False,
        "warnings": [],
        "extracted_files": [],
        "password_protected": False,
        "compression_ratio": 0,
    }

    try:
        with zipfile.ZipFile(file_path, "r") as zf:
            infolist = zf.infolist()

            if len(infolist) > MAX_FILES_PER_ARCHIVE:
                report["warnings"].append(
                    f"Archive ignorée : {len(infolist)} fichiers > limite de {MAX_FILES_PER_ARCHIVE} "
                    f"(comportement typique de zip-bomb)"
                )
                return report

            report["password_protected"] = _zip_is_password_protected(zf)
            if report["password_protected"]:
                report["warnings"].append(
                    "Archive protégée par mot de passe — contenu non analysable, "
                    "technique fréquente pour contourner les antivirus par e-mail"
                )
                return report

            ratio = _zip_compression_ratio(zf)
            report["compression_ratio"] = round(ratio, 1)
            if ratio > MAX_COMPRESSION_RATIO:
                report["warnings"].append(
                    f"Ratio de compression anormal ({ratio:.0f}:1) — possible zip-bomb, extraction annulée"
                )
                return report

            total_uncompressed = sum(i.file_size for i in infolist)
            if total_uncompressed > MAX_TOTAL_EXTRACTED_BYTES:
                report["warnings"].append(
                    f"Taille décompressée totale ({total_uncompressed // (1024*1024)} Mo) "
                    f"> limite de {MAX_TOTAL_EXTRACTED_BYTES // (1024*1024)} Mo — extraction annulée"
                )
                return report

            os.makedirs(extract_to, exist_ok=True)
            extracted_bytes = 0

            for info in infolist:
                if info.is_dir():
                    continue
                if info.file_size > MAX_SINGLE_FILE_BYTES:
                    report["warnings"].append(f"Fichier ignoré (trop volumineux) : {info.filename}")
                    continue

                safe_path = _safe_extract_path(extract_to, info.filename)
                if safe_path is None:
                    report["warnings"].append(f"Fichier ignoré (chemin suspect / zip-slip) : {info.filename}")
                    continue

                extracted_bytes += info.file_size
                if extracted_bytes > MAX_TOTAL_EXTRACTED_BYTES:
                    report["warnings"].append("Limite globale d'extraction atteinte — extraction interrompue")
                    break

                os.makedirs(os.path.dirname(safe_path), exist_ok=True)
                try:
                    with zf.open(info, "r") as src, open(safe_path, "wb") as dst:
                        shutil.copyfileobj(src, dst, length=1024 * 1024)
                    report["extracted_files"].append({
                        "member_name": info.filename,
                        "extracted_path": safe_path,
                    })
                except (RuntimeError, zipfile.BadZipFile) as e:
                    # RuntimeError levée par zipfile si le fichier est chiffré sans mdp fourni
                    report["warnings"].append(f"Extraction impossible pour {info.filename} : {e}")

            report["ok"] = True
            return report

    except zipfile.BadZipFile:
        report["warnings"].append("Archive ZIP corrompue ou invalide")
        return report
    except Exception as e:
        report["warnings"].append(f"Erreur d'extraction : {e}")
        return report


def analyze_archive(file_path: str, original_name: str = "", _depth: int = 0) -> dict:
    """
    Extrait puis rescanne récursivement le contenu d'une archive ZIP.
    Gère les zip-in-zip jusqu'à MAX_ARCHIVE_DEPTH, avec protections
    anti zip-bomb, zip-slip et détection des archives chiffrées.
    """
    result = {
        "is_archive":          True,
        "password_protected":  False,
        "compression_ratio":   0,
        "depth":               _depth,
        "warnings":            [],
        "sub_scans":           [],
        "archive_malicious":   False,
    }

    if _depth >= MAX_ARCHIVE_DEPTH:
        result["warnings"].append(
            f"Profondeur maximale d'imbrication atteinte ({MAX_ARCHIVE_DEPTH}) — "
            f"archives imbriquées suspectes, arrêt de la récursion"
        )
        result["archive_malicious"] = True
        return result

    if not _is_zip_file(file_path):
        result["warnings"].append("Format d'archive non supporté pour l'extraction récursive (seul ZIP l'est actuellement)")
        return result

    scratch_id = f"{os.path.basename(file_path)}_{int(time.time()*1000)}_{_depth}"
    extract_dir = os.path.join(ARCHIVE_SCRATCH_DIR, scratch_id)

    extraction = _extract_zip_safely(file_path, extract_dir)
    result["warnings"].extend(extraction["warnings"])
    result["password_protected"] = extraction["password_protected"]
    result["compression_ratio"]  = extraction["compression_ratio"]

    if extraction["password_protected"] or not extraction["ok"]:
        # Archive chiffrée ou refusée (bomb, trop de fichiers...) = suspecte par défaut
        result["archive_malicious"] = True
        _cleanup_scratch(extract_dir)
        return result

    try:
        for entry in extraction["extracted_files"]:
            sub_path = entry["extracted_path"]
            sub_name = entry["member_name"]

            sub_report = analyze_file(sub_path, original_name=sub_name, _skip_archive_scan=True)

            if _is_zip_file(sub_path):
                nested = analyze_archive(sub_path, original_name=sub_name, _depth=_depth + 1)
                sub_report["archive_scan"] = nested
                if nested["archive_malicious"]:
                    sub_report["is_malicious"] = True
                    sub_report["status"] = "malicious"

            result["sub_scans"].append(sub_report)
            if sub_report.get("is_malicious"):
                result["archive_malicious"] = True
    finally:
        _cleanup_scratch(extract_dir)

    return result


def _cleanup_scratch(path: str):
    try:
        if os.path.exists(path):
            shutil.rmtree(path, ignore_errors=True)
    except Exception:
        pass


def analyze_file(file_path: str, original_name: str = "", _skip_archive_scan: bool = False) -> dict:
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

    # Les règles "info" (identification de type de fichier) ne doivent pas
    # à elles seules déclencher un statut "malicious".
    real_matches = [m for m in matches if str((m.meta or {}).get("severity", "")).lower() != "info"]

    is_malicious = len(real_matches) > 0
    severity     = _severity_from_matches(real_matches) if is_malicious else "none"

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

    result = {
        "status":        "malicious" if is_malicious else "clean",
        "is_malicious":  is_malicious,
        "severity":      severity,
        "file_name":     original_name or os.path.basename(file_path),
        "file_size_kb":  round(file_size / 1024, 2),
        "sha256":        sha256,
        "rules_matched": len(real_matches),
        "categories":    categories,
        "matches":       match_details,
        "rules_source":  _rules_source,   # "builtin" ou "community"
        "scanned_at":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }

    # Si c'est un ZIP, on extrait et on rescanne récursivement son contenu
    # (sauf si on est déjà appelé depuis analyze_archive, qui gère elle-même
    # la récursion pour éviter un double scan).
    if not _skip_archive_scan and _is_zip_file(file_path):
        archive_report = analyze_archive(file_path, original_name=result["file_name"])
        result["archive_scan"] = archive_report
        if archive_report["archive_malicious"]:
            result["is_malicious"] = True
            result["status"] = "malicious"
            if result["severity"] in ("none", "low"):
                result["severity"] = "high"

    return result


# Auto-update en background

def start_auto_update(blocking_init: bool = True):
    """
    Lance le moteur.
    - blocking_init=True (recommandé) : télécharge/compile les règles
      immédiatement et de façon SYNCHRONE au démarrage (donc l'outil
      attend d'avoir un moteur prêt avant de continuer), puis stocke
      tout en local pour les prochains lancements hors-ligne.
    - Ensuite, un thread de fond relance update_rules() toutes les 24h.
    """
    if blocking_init:
        init_engine()

    def _worker():
        if not blocking_init:
            update_rules()
        while True:
            time.sleep(UPDATE_INTERVAL)
            update_rules()

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    print("[*] YARA : auto-update activé (toutes les 24h)")