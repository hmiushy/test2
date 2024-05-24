#!/usr/bin/env python3
import random
import socket
import sys

from comp_miu import *

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def main():

    if len(sys.argv)<3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    iface = get_if()
    macdst = "08:00:00:00:01:00"
    #macdst = "ff:ff:ff:ff:ff:ff"
    print("sending on interface %s to %s" % (iface, str(addr)))
    pkt =  Ether(src=get_if_hwaddr(iface), dst=macdst)
    ## Usual packet
    #pkt = pkt /IP(src=src,dst=dst,proto=17)/UDP(dport=1234,sport=random.randint(49152,65535))
    pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    #pkt = pkt /IP(dst=addr) / UDP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]

    ## debug
    #pkt = Ether(src=get_if_hwaddr(iface), dst=macdst) /IP(dst=addr,proto=TYPE_COMP)/COMP(compType=TYPE_COMP)/COMP(compType=TYPE_COMP)/COMP(compType=TYPE_COMP)/COMP(compType=17)/UDP() #/ sys.argv[2]
    pkt.show()
    #for i in range(4):
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
