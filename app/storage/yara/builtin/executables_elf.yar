
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
