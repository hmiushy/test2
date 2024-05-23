from scapy.all import *

TYPE_COMP = 0x1212
TYPE_IPV4 = 0x0800

class COMP(Packet):
   name = "TYPE_COMP"
   fields_desc = [BitField("srcAddr", 0, 32),
                  BitField("dstAddr", 0, 32),
                  BitField("srcPort", 0, 16),
                  BitField("dstPort", 0, 16),
                  BitField("protocol", 0, 8),
                  BitField("compType", 0, 16)]


bind_layers(Ether, IP, type=TYPE_IPV4)
bind_layers(Ether, COMP, type=TYPE_COMP)
bind_layers(COMP, COMP)
bind_layers(COMP, IP, type=TYPE_IPV4)
