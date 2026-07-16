
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
