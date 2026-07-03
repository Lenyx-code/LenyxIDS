#!/bin/bash
echo "[*] Configuration du routage..."

# Activer le forwarding IP
echo 1 > /proc/sys/net/ipv4/ip_forward

# Activer promisc sur les 2 interfaces
ip link set eth0 promisc on
ip link set eth1 promisc on

# Forcer l'attaquant à passer par le backend pour joindre la victime
# Route statique : pour joindre 172.20.0.x, passer par le backend
ip route add 172.19.0.0/24 dev eth1 2>/dev/null || true

echo "[*] Routage configuré"
echo "[*] eth0 (frontend) : $(ip addr show eth0 | grep 'inet ' | awk '{print $2}')"
echo "[*] eth1 (backend)  : $(ip addr show eth1 | grep 'inet ' | awk '{print $2}')"