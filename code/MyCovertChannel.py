from CovertChannelBase import CovertChannelBase
from scapy.all import DNS, DNSQR, IP, UDP, sniff, send

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
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        isEven = len(binary_message) % 2 != 0

        encoding = {
            "00" : 3,
            "01" : 4,
            "10" : 7,
            "11" : 8,
            "1" : 9,
            "0" : 10
        }

        
        for i in range(0, int(len(binary_message) / 2)):
            twoBits = binary_message[(2 * i) : (2 * i) + 2]
            fireThis = encoding[twoBits]
            dnsPacket = IP(dst=destIP) / UDP(dport=dnsPort) / DNS(qd=DNSQR(qname=domainToQuery, qtype=fireThis))
            send(dnsPacket)

        if not isEven:
            fireThis = encoding[binary_message[-1]]
            dnsPacket = IP(dst=destIP) / UDP(dport=dnsPort) / DNS(qd=DNSQR(qname=domainToQuery, qtype=fireThis))
            send(dnsPacket)

    
    def receive(self, interface, dnsPort, log_file_name, srcIP):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        binaryMessage = ""
        stringReceived = ""
        decoding = {
            3 : "00",
            4 : "01",
            7 : "10",
            8 : "11",
            9 : "1",
            10 : "0"
        }

        def packetDecoder(packet):
            nonlocal binaryMessage
            print("Received 1 packet.\n")
            if (packet.haslayer(DNS)) and (packet[IP].src == srcIP):
                qType = packet[DNS].qd.qtype
                if (qType in [3,4,7,8,9,10]):
                    binaryMessage += (decoding[qType])
                    


        def shallIStop(packet):
            if binaryMessage.endswith("00101110"):
                return True
            
        #stop_filter=shallIStop timeout=takeATimeOut

        sniff(iface=interface, filter="udp port " + str(dnsPort), prn=packetDecoder, stop_filter=shallIStop )
        for i in range(0, len(binaryMessage), 8):
            stringReceived += self.convert_eight_bits_to_character(binaryMessage[i:i+8])

        self.log_message(stringReceived, log_file_name)
