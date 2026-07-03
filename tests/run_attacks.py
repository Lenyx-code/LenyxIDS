import sys
import time
import subprocess as sp


VICTIM_IP = "172.19.0.3"

ATTACKS = {
    "scan":  ("Port Scan SYN",        "python attacks/port_scan.py"),
    #"flood": ("Ping Flood DoS",       "python attacks/ping_flood.py"),
    #"brute": ("Brute Force SSH+HTTP", "python attacks/brute_force.py both"),
    #"arp":   ("ARP Spoofing",         "python attacks/arp_spoof.py spoof"),
}

def run_attack(name, cmd):
    print(f"\n{'='*50}")
    print(f" TEST ATTAQUE : {name}")
    print(f"{'='*50}")
    result = sp.run(cmd, shell=True)
    if result.returncode != 0:
        print(f"[!] Erreur durant {name}")
    time.sleep(1)

if __name__ == "__main__":
    print("Simulation: Attaquant : 172.19.0.4 > Victime: 172.19.0.3")
    mode = sys.argv[1] if len(sys.argv) > 1 else "all"
 
    if mode == "all":
        for key, (name, cmd) in ATTACKS.items():
            run_attack(name, cmd)
    elif mode in ATTACKS:
        name, cmd = ATTACKS[mode]
        run_attack(name, cmd)
    else:
        print(f"Usage: python run_attacks.py [all|{'|'.join(ATTACKS.keys())}]")
        sys.exit(1)
 
    print(f"\n[✓] Simulation terminée")
