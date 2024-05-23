#!/usr/bin/env python3
import os
import sys
from scapy.all import *
from comp_miu import *

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x
def packet_callback(packet):
    data = str(packet.show)
    data_layers = [l for l in expand(packet) if l.name=='TYPE_COMP']
    print(data_layers)
    pattern = "(.*)tos=0x(.*)"
    global count
    count = 1
    print(packet.show())
    d = re.search(pattern, data)
    if "tos" in data:
        dd = d.group(2).split(' ')
        dd[0] = int(dd[0], 16)
        print("Packet Count: {0}".format(count))


def main():
    iface = "eth0"
    ipv4dstAddr = "10.0.2.2"
    print("sniffing on {}".format(iface))
    # sniff(filter="ip host "+ipv4dstAddr, iface=iface,
    #       prn= lambda x:packet_callback(x))
    sniff(iface=iface,
          prn= lambda x:packet_callback(x))


if __name__ == '__main__':
    main()
