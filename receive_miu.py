#!/usr/bin/env python3
import os
import sys
from scapy.all import *
from comp_miu import *
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp
import time
import re

def my_parse(data):
    pkt = bytes(packet)
    TCMP_PROTO = 1
    TCP_PROTO = 6
    UDP_PROTO = 17
    COMP_PROTO = 146

    ETHERNET_HEADER_LENGTH = 14
    IP_HEADER_LENGTH = 20
    ICMP_HEADER_LENGTH = 8
    UDP_HEADER_LENGTH = 8
    TCP_HEADER_LENGTH = 20
    COMP_HEADER_LENGTH = 14
    
    raw = bytes(packet) # to get payload
    v1 = ETHERNET_HEADER_LENGTH + IP_HEADER_LENGTH
    #print(raw)
    print(packet[v1+1:COMP_HEADER_LENGTH])

def expand(x):
    yield x
    while x.payload:
        x = x.payload
        yield x
global count
count = 0
def packet_callback(packet):
    pkt = bytes(packet)
    global count
    data = str(packet.show)
    TCMP_PROTO = 1
    TCP_PROTO = 6
    UDP_PROTO = 17
    COMP_PROTO = 146

    ETHERNET_HEADER_LENGTH = 14
    IP_HEADER_LENGTH = 20
    ICMP_HEADER_LENGTH = 8
    UDP_HEADER_LENGTH = 8
    TCP_HEADER_LENGTH = 20
    COMP_HEADER_LENGTH = 14
    
    print(" ----------------------------------- packet-in -----------------------------------")
    indent = " "
    now_indent = indent
    ## Ethernet header report ## ------------------------
    pre_pos = 0
    end_pos = ETHERNET_HEADER_LENGTH
    eth_report = Ether(pkt[pre_pos:end_pos])
    eth_report.show2()    
    ## IPv4 header report ## ------------------------
    pre_pos = end_pos
    end_pos += IP_HEADER_LENGTH
    ip_report = IP(pkt[pre_pos:end_pos])
    ip_report.show2(lvl=now_indent)
    
    if ip_report.proto == TYPE_COMP:
        ## COMP header report ## ------------------------
        compType = TYPE_COMP
        comp_header_count = 1
        while compType == TYPE_COMP:
            print("### [COMP HEADER {}] ###".format(comp_header_count))
            comp_header_count += 1
            pre_pos = end_pos
            end_pos += COMP_HEADER_LENGTH
            comp_report = COMP(pkt[pre_pos:end_pos])
            for cnt in range(comp_header_count):
                now_indent += indent
            comp_report.show2(lvl=now_indent)
            compType = comp_report.compType
        ## TCP header report ## ------------------------
        if compType == TCP_PROTO:
            pre_pos = end_pos
            end_pos += TCP_HEADER_LENGTH
            tcp_report = TCP(pkt[pre_pos:end_pos])
            now_indent += indent
            tcp_report.show2(lvl=now_indent)
        elif compType == UDP_PROTO:
            pre_pos = end_pos
            end_pos += UDP_HEADER_LENGTH
            udp_report = UDP(pkt[pre_pos:end_pos])
            now_indent += indent
            udp_report.show2(lvl=now_indent)
      
    count += 1
    print("packet count: {}".format(count))
def main():
    iface = "eth0"
    ipv4dstAddr = "10.0.2.2"
    print("sniffing on {}".format(iface))
    sniff(iface=iface,filter="ip host "+ipv4dstAddr,
          prn= lambda x:packet_callback(x))


if __name__ == '__main__':
    main()
