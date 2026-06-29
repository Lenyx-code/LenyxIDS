
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
