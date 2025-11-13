#!/usr/bin/env python3
import socket
from scapy.all import DNS, DNSRR, DNSRROPT, DNSQR

IP = "0.0.0.0"
PORT = 53

def build_big_dns_response(query):
    name = query.qd.qname if query.qd else b"ciao.com."

    answers = []
    big_txt = "X" * 300

    for _ in range(20):
        answers.append(DNSRR(rrname=name, type="TXT", ttl=300, rdata=big_txt))

    # EDNS0 (ammesso nella section "ar")
    opt = DNSRROPT(rclass=4096)

    # Costruzione risposta DNS completa
    response = DNS(
        id=query.id,
        qr=1, aa=1, rd=1,
        qd=query.qd,
        ancount=len(answers),
        an=answers,
        ar=opt
    )

    return response


def main():
    print(f"[*] Finto DNS in ascolto su {IP}:{PORT} (UDP)")
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((IP, PORT))

    while True:
        data, client = sock.recvfrom(8192)
        try:
            query = DNS(data)
            print(f"[+] Query da {client[0]}:{client[1]} → {query.qd.qname if query.qd else '??'}")
        except:
            print("[!] Pacchetto non-DNS ignorato.")
            continue

        response = build_big_dns_response(query)
        sock.sendto(bytes(response), client)
        print(f"[+] Risposta gigante inviata a {client[0]}:{client[1]}\n")


if __name__ == "__main__":
    main()
