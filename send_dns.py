#!/bin/python

from scapy.all import *

Qdsec  = DNSQR(qname="aaaaa.example.com")
dns    = DNS(id=0xAAAA, qr=0, qdcount=1, ancount=0, nscount=0,arcount=0, qd=Qdsec)
ip  = IP(dst="192.168.0.13", src="192.168.0.10")
udp = UDP(dport=53, sport=50010, chksum=0)
request = ip/udp/dns
with open("ip_req.bin", "wb") as binary_file:
	binary_file.write(bytes(request))
send(request)



