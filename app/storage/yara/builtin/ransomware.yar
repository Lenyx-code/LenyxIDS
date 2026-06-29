
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
