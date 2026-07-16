
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
