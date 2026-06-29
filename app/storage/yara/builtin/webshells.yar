
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
