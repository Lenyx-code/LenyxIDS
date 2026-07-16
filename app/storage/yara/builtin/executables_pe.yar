
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
