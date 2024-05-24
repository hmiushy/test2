from scapy.all import *

#TYPE_COMP = 0x1212
TYPE_COMP = 146
TYPE_IPV4 = 0x0800

class COMP(Packet):
   name = "TYPE_COMP"
   fields_desc = [BitField("srcAddr", 0, 32),
                  BitField("dstAddr", 0, 32),
                  BitField("srcPort", 0, 16),
                  BitField("dstPort", 0, 16),
                  BitField("protocol", 0, 8),
                  BitField("compType", 0, 8)]


bind_layers(Ether, IP, type=TYPE_IPV4)
#bind_layers(IP, COMP, proto=TYPE_COMP, compType=TYPE_COMP)
bind_layers(IP, COMP, proto=TYPE_COMP)
#bind_layers(COMP, COMP)
bind_layers(COMP, COMP, compType=TYPE_COMP)
bind_layers(COMP, ICMP, compType=1)
bind_layers(COMP, TCP,  compType=6)
bind_layers(COMP, UDP,  compType=17)
bind_layers(COMP, ESP,  compType=50)


