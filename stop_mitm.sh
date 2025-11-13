#!/bin/bash

echo "[*] Arresto arpspoof..."
sudo killall arpspoof > /dev/null 2>&1

echo "[*] Disabilito IP forwarding..."
echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward > /dev/null

echo "[*] Pulizia ARP cache locale (facoltativa)..."
# Svuota ARP della vittima (opzionale, da fare sulla vittima)
# sudo arp -d 192.168.1.1

echo "[+] MITM DISATTIVATO"
echo "    La rete è tornata normale."
