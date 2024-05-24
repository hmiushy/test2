#!/usr/bin/env python3
import random
import socket
import sys

from comp_miu import *

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp

def main():
    dst = "10.0.2.2"
    src = "10.0.1.1"
    ## debug
    #pkt = Ether(type=0x800)/IP(src=src,dst=dst,proto=TYPE_COMP)/COMP(compType=TYPE_COMP)/COMP(compType=TYPE_COMP)/COMP(compType=TYPE_COMP)/COMP(compType=6)/TCP()
    pkt = Ether(type=0x800)/IP(src=src,dst=dst,proto=TYPE_COMP)/COMP(compType=TYPE_COMP)/COMP(compType=TYPE_COMP)/COMP(compType=TYPE_COMP)/COMP(compType=17)/UDP()

    ## Usual packet
    #pkt = Ether(type=0x800)/IP(src=src,dst=dst,proto=17)/UDP(dport=1234,sport=random.randint(49152,65535))
    
    pkt.show()
    sendp(pkt, iface="eth0")

if __name__ == '__main__':
    main()
