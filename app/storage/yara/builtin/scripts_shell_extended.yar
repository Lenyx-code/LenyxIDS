
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
