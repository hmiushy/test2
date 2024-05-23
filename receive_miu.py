#!/usr/bin/env python3
import os
import sys
from scapy.all import *
from comp_miu import *
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp
import time

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x
def packet_callback(packet):
    bind_layers(Ether, IP, type=TYPE_IPV4)
    bind_layers(Ether, COMP, type=TYPE_COMP)
    bind_layers(COMP, COMP, type=TYPE_COMP)
    bind_layers(COMP, IP, type=TYPE_IPV4) 
    packet.show()

def main():
    iface = "eth0"
    ipv4dstAddr = "10.0.2.2"
    print("sniffing on {}".format(iface))
    # sniff(filter="ip host "+ipv4dstAddr, iface=iface,
    #       prn= lambda x:packet_callback(x))
    sniff(iface=iface,#filter="ip host "+ipv4dstAddr,
          prn= lambda x:packet_callback(x))


if __name__ == '__main__':
    main()
