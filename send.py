#!/usr/bin/env python3
import random
import socket
import sys

from comp_miu import *

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp

def main():
    #pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]

    for i in range(4):
        ip = "10.0.2.2"
        pkt = Ether()/IP(dst=ip) /UDP(dport=1234,sport=random.randint(49152,65535))
        """ debug """
        # pkt = Ether()/IP(dst=ip)
        # pkt = Ether()/COMP(compType=0x800)/IP(dst=ip)
        # pkt = Ether()/COMP(compType=0x1212)/COMP(compType=0x800)/IP(dst=ip)
        # pkt = Ether()/COMP(compType=0x1212)/COMP(compType=0x1212)/COMP(compType=0x800)/IP(dst=ip)
        # pkt = Ether()/COMP(compType=0x1212)/COMP(compType=0x1212)/COMP(compType=0x1212)/COMP(compType=0x800)/IP(dst=ip)
        pkt.show()
        sendp(pkt, iface="eth0")


if __name__ == '__main__':
    main()
