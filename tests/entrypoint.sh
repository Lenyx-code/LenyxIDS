#!/bin/bash

ROLE=${ROLE:-"attacker"}

# ── Agent IDS ─────────────────────────────────────────────────────
AGENT_PIDFILE="/tmp/ids_agent.pid"

start_agent() {
    if [ -f "$AGENT_PIDFILE" ]; then
        EXISTING_PID=$(cat "$AGENT_PIDFILE")
        if kill -0 "$EXISTING_PID" 2>/dev/null; then
            echo "[*] Agent déjà en cours (pid $EXISTING_PID) — skip"
            return
        fi
    fi

    # Chercher agent.py dans les emplacements possibles
    AGENT_PATH=""
    for p in /agent.py /tests/agent.py agent.py; do
        [ -f "$p" ] && AGENT_PATH="$p" && break
    done

    if [ -z "$AGENT_PATH" ]; then
        echo "[!] agent.py introuvable — agent non démarré"
        return
    fi

    python "$AGENT_PATH" \
        --mode mongo \
        --mongo mongodb://database-mongo:27017/ \
        --interval 5 \
        -v &
    AGENT_PID=$!
    echo $AGENT_PID > "$AGENT_PIDFILE"
    echo "[*] Agent IDS démarré depuis $AGENT_PATH (pid $AGENT_PID)"
}

start_agent

# ── Rôles ─────────────────────────────────────────────────────────

if [ "$ROLE" = "victim" ]; then
    echo "[*] Démarrage en mode VICTIME"

    ip route replace default via 172.20.0.2
    echo "[+] Gateway → 172.20.0.2 (backend)"

    mkdir -p /var/www/html/api
    cat << 'EOF' > /var/www/html/index.html
<!DOCTYPE html>
<html>
<head><title>PME Portail Interne</title></head>
<body>
    <h1>Bienvenue sur le réseau local</h1>
    <form action="/api/search.php" method="GET">
        <input type="text" name="q" placeholder="Rechercher un employé...">
        <input type="submit" value="Chercher">
    </form>
</body>
</html>
EOF

    service ssh start   && echo "[+] SSH démarré sur port 22"
    service apache2 start && echo "[+] HTTP démarré sur port 80"

    echo "[*] Ports actifs :"
    ss -tlnp | grep -E '22|80'

    echo "[*] Victime prête"
    tail -f /dev/null

elif [ "$ROLE" = "attacker" ]; then
    echo "[*] Démarrage en mode ATTAQUANT"

    echo 1 > /proc/sys/net/ipv4/ip_forward
    echo "[+] IP forwarding activé"

    BACKEND_IF=$(ip -4 route show 172.20.0.0/24 2>/dev/null | awk '{
        for(i=1;i<=NF;i++) if($i=="dev") print $(i+1)
    }' | head -1)

    if [ -z "$BACKEND_IF" ]; then
        ip route add 172.20.0.0/24 via 172.19.0.2 2>/dev/null \
            && echo "[+] Route ajoutée : 172.20.0.0/24 via 172.19.0.2" \
            || echo "[!] Route déjà existante ou échec"
    else
        echo "[+] Connexion directe au réseau backend sur $BACKEND_IF"
    fi

    echo "[*] Config réseau :"
    ip route

    echo "[*] Attaquant prêt"
    tail -f /dev/null
fi