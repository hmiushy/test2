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
global count
count = 0
def packet_callback(packet):
    global count
    print("----------------------------------------------------")
    count += 1
    packet.show()
    print("packet count: {}".format(count))
def main():
    iface = "eth0"
    ipv4dstAddr = "10.0.2.2"
    print("sniffing on {}".format(iface))
    sniff(iface=iface,#filter="ip host "+ipv4dstAddr,
          prn= lambda x:packet_callback(x))


if __name__ == '__main__':
    main()
