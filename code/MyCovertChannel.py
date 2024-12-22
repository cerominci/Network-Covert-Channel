from CovertChannelBase import CovertChannelBase
from scapy.all import DNS, DNSQR, IP, UDP, sniff, send
import time

class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass
    def send(self, log_file_name, destIP, dnsPort, domainToQuery):
        """

        For the first step, we create a binary message using the provided functions in the class CCB. We then check if binary message has an even or odd length.
        This is not necessary for we know that it will be of even length, but for generalization I wanted to add this. CC capacity measurement is not affected by that part.
        To maximize covert channel capacity we send 2 bits each time, as per the HW description.

        In RFC 1035 the following value-class pairs are given:
        IN - 1
        CS - 2 (obsolete)
        CH - 3
        HS - 4

        To maximize CC capacity, we send 2 bits. But to do this we also must use CS - 2, which is obsolete. This reduces stealth of the channel. 
        We then iterate over the binary messages, selecting 2 bits each time. We then encode them, craft the DNS packet for the provided hostname and send this DNS packet.

        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        isEven = len(binary_message) % 2 == 0

        encoding = {
            "00" : 1,
            "01" : 3,
            "10" : 4,
            "11" : 2,
            
        }

        t0 = time.time()
        for i in range(0, int(len(binary_message) / 2)):
            twoBits = binary_message[(2 * i) : (2 * i) + 2]
            fireThis = encoding[twoBits]
            dnsPacket = IP(dst=destIP) / UDP(dport=dnsPort) / DNS(qd=DNSQR(qname=domainToQuery, qclass=fireThis))
            send(dnsPacket)
        t1 = time.time()
        

        if not isEven:
            fireThis = encoding[binary_message[-1]]
            dnsPacket = IP(dst=destIP) / UDP(dport=dnsPort) / DNS(qd=DNSQR(qname=domainToQuery, qclass=fireThis))
            send(dnsPacket)
        print(f"CC capacity: {128 / (t1-t0)}")
        

    
    def receive(self, interface, dnsPort, log_file_name, srcIP):
        """
        binaryMessage here is the received encoded form of the message. stringReceived is the decoded form of it. 
        We define a packetDecoder function, that will append to binaryMessage, only if the captureed packet is a DNS packet, and is from the srcIP.
        We filter by these parameters to make sure legitimate communication over other protocols with srcIP, and legitimate DNS communication with different IP's are not affected.
        This part can be modified after talking with the TA.
        The function shallIStop is called for each packet. It checks if the binaryMessage contains the binary form of: \".\"
        We then sniff over the provided interface and port number. 
        DNS port is modifiable because although by default it works over 53, it can be customized. Again, generalization.
        Once shallIStop returns true and capturing stops, we start converting the binary message to ASCII.

        """
        binaryMessage = ""
        stringReceived = ""
        decoding = {
            1 : "00",
            3 : "01",
            4 : "10",
            2 : "11",
        }

        def packetDecoder(packet):
            nonlocal binaryMessage
            print("Received 1 packet.\n")
            if (packet.haslayer(DNS)) and (packet[IP].src == srcIP):
                qClass = packet[DNS].qd.qclass
                if (qClass in [1, 3, 4, 2]):
                    binaryMessage += (decoding[qClass])
                    
        def shallIStop(packet):
            if binaryMessage.endswith("00101110"):
                return True

        sniff(iface=interface, filter="udp port " + str(dnsPort), prn=packetDecoder, stop_filter=shallIStop )
        for i in range(0, len(binaryMessage), 8):
            stringReceived += self.convert_eight_bits_to_character(binaryMessage[i:i+8])

        self.log_message(stringReceived, log_file_name)
