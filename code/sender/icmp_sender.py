from scapy.all import ICMP, IP, send

destination =  "172.19.0.2" 

packet = IP(dst=destination, ttl=1) / ICMP()


send(packet, count=1)
