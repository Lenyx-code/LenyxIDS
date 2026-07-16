
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
