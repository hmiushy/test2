#!/usr/bin/env python3
import random
import socket
import sys
from comp_header import comp
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
    ip = "10.0.2.2"

    pkt =  Ether()/IP(dst=ip) /TCP(dport=1234,sport=random.randint(49152,65535))
    #pkt = pkt /IP(dst=addr) / TCP(dport=1234, sport=random.randint(49152,65535)) / sys.argv[2]
    pkt.show2()
    sendp(pkt, iface="eth0")


if __name__ == '__main__':
    main()
