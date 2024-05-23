from scapy.all import *


TYPE_COMP = 0x1212
TYPE_IPV4 = 0x0800


class IPv4Data(Packet):
   name = 'IPv4Data'
   fields_desc = [ BitField("version", 0, 4),
                   BitField("ihl", 0, 4),
                   BitField("tos", 0, 8),
                   BitField("totalLen", 0, 16),
                   BitField("identification", 0, 16),
                   BitField("flags", 0, 3),
                   BitField("flagOffset", 0, 13),
                   BitField("ttl", 0, 8),
                   BitField("protocol", 0, 8),
                   BitField("hdrChecksum", 0, 16),
                   SourceIPField("srcAddr", 0),
                   SourceIPField("dstAddr", 0),
                   BitField("options", 0, 32)]

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
bind_layers(COMP, COMP, type=0)
bind_layers(COMP, IP, type=TYPE_IPV4)
