#!/bin/bash

ROLE=${ROLE:-"attacker"}

if [ "$ROLE" = "victim" ]; then
    echo "[*] Démarrage en mode VICTIME"

    # Forcer le trafic à passer par le backend → sniffer voit tout
    ip route replace default via 172.20.0.2
    echo "[+] Gateway → 172.20.0.2 (backend)"

    # Démarrer SSH
    service ssh start
    echo "[+] SSH démarré sur port 22"

    # Démarrer Apache HTTP
    service apache2 start
    echo "[+] HTTP démarré sur port 80"

    echo "[*] Vérification ports :"
    ss -tlnp | grep -E '22|80'

    echo "[*] Services actifs — victime prête"
    tail -f /dev/null

elif [ "$ROLE" = "attacker" ]; then
    echo "[*] Démarrage en mode ATTAQUANT"

    # Activer le forwarding IP (nécessaire pour ARP spoofing MITM)
    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "[+] IP forwarding activé"

    # BUG — 'ip route show' retourne l'interface avec 'dev', pas le 3ème champ
    # AVANT : BACKEND_IF=$(ip -4 route show 172.20.0.0/24 | awk '{print $3}')
    # APRÈS :
    BACKEND_IF=$(ip -4 route show 172.20.0.0/24 | awk '{
        for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)
    }')

    echo "[+] Interface backend détectée : $BACKEND_IF"

    # Si pas de route directe → ajouter via le backend frontend
    if [ -z "$BACKEND_IF" ]; then
        ip route add 172.20.0.0/24 via 172.19.0.2 2>/dev/null && \
            echo "[+] Route ajoutée : 172.20.0.0/24 via 172.19.0.2" || \
            echo "[!] Route déjà existante"
    else
        echo "[+] Connexion directe au réseau backend sur $BACKEND_IF"
    fi

    echo "[*] Config réseau finale :"
    ip route
    echo ""
    ip a show eth0 | grep inet
    ip a show eth1 2>/dev/null | grep inet || true

    echo "[*] Attaquant prêt"
    tail -f /dev/null
fi