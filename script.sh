## memo
simple_switch_CLI --thrift-port 9090
register_write now_array 0 0
register_read now_array
register_read debug


# ###[ Ethernet ]### 
#   dst       = 08:00:00:00:02:22
#   src       = 08:00:00:00:01:00
#   type      = IPv4
# ###[ IP ]### 
#      version   = 4
#      ihl       = 5
#      tos       = 0x0
#      len       = 32
#      id        = 1
#      flags     = 
#      frag      = 0
#      ttl       = 63
#      proto     = 146
#      chksum    = 0x6449
#      src       = 10.0.1.1
#      dst       = 10.0.2.2
#      \options   \
# ###[ TYPE_COMP ]### 
#         srcAddr   = 167772417
#         dstAddr   = 167772674
#         srcPort   = 56135
#         dstPort   = 1234
#         protocol  = 0
#         compType  = 0
# ###[ Padding ]### 
#            load      = '\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xc1\xe5\x04\xd2\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xfd\xc5\x04\xd2\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xddP\x04\xd2\x11\x11\xddP\x04\xd2\x00\x0c\xa4N1111'
#  '\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xc1\xe5\x04\xd2\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xfd\xc5\x04\xd2\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xddP\x04\xd2\x11\x11\xddP\x04\xd2\x00\x0c\xa4N1111'
#   \x11\x92\n\x00\x01\x01\n\x00\x02\x02\xc1\xe5\x04\xd2\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xfd\xc5\x04\xd2\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xddP\x04\xd2\x11\x11\xddP\x04\xd2\x00\x0c\xa4N1111'
# b'\x08\x00\x00\x00\x02"\x08\x00\x00\x00\x01\x00\x08\x00E\x00\x00 \x00\x01\x00\x00?\x92dI\n\x00\x01\x01\n\x00\x02\x02\n\x00\x01\x01\n\x00\x02\x02\xdbG\x04\xd2\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xc1\xe5\x04\xd2\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xfd\xc5\x04\xd2\x11\x92\n\x00\x01\x01\n\x00\x02\x02\xddP\x04\xd2\x11\x11\xddP\x04\xd2\x00\x0c\xa4N1111'
# packet count: 7
# ----------------------------------------------------
# ###[ Ethernet ]### 
#   dst       = 08:00:00:00:02:00
#   src       = 08:00:00:00:02:22
#   type      = IPv4
# ###[ IP ]### 
#      version   = 4
#      ihl       = 5
#      tos       = 0xc0
#      len       = 60
#      id        = 63213
#      flags     = 
#      frag      = 0
#      ttl       = 64
#      proto     = icmp
#      chksum    = 0x6c11
#      src       = 10.0.2.2
#      dst       = 10.0.1.1
#      \options   \
# ###[ ICMP ]### 
#         type      = dest-unreach
#         code      = protocol-unreachable
#         chksum    = 0x5e1
#         reserved  = 0
#         length    = 0
#         nexthopmtu= 0
# ###[ IP in ICMP ]### 
#            version   = 4
#            ihl       = 5
#            tos       = 0x0
#            len       = 32
#            id        = 1
#            flags     = 
#            frag      = 0
#            ttl       = 63
#            proto     = 146
#            chksum    = 0x6449
#            src       = 10.0.1.1
#            dst       = 10.0.2.2
#            \options   \
# ###[ TYPE_COMP ]### 
#               srcAddr   = 167772417
#               dstAddr   = 167772674
#               srcPort   = 56135
#               dstPort   = 1234
#               protocol  = 0
#               compType  = 0

# b'\x08\x00\x00\x00\x02\x00\x08\x00\x00\x00\x02"\x08\x00E\xc0\x00<\xf6\xed\x00\x00@\x01l\x11\n\x00\x02\x02\n\x00\x01\x01\x03\x02\x05\xe1\x00\x00\x00\x00E\x00\x00 \x00\x01\x00\x00?\x92dI\n\x00\x01\x01\n\x00\x02\x02\n\x00\x01\x01\n\x00\x02\x02\xdbG\x04\xd2'
# packet count: 8
sniffing on eth0
sniffing on eth0
sniffing on eth0
packet count: 1
packet count: 2
sniffing on eth0
sniffing on eth0
