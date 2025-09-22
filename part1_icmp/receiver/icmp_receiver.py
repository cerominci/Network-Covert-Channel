from scapy.all import sniff, ICMP, IP

def packet_callback(packet):
    if packet.haslayer(ICMP) and packet[IP].ttl == 1:
        packet.show()

sniff(filter="icmp", prn=packet_callback)

# Implement your ICMP receiver here
