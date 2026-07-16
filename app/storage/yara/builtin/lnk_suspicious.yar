
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
