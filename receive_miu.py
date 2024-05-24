#!/usr/bin/env python3
import os
import sys
from scapy.all import *
from comp_miu import *
from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp
import time
import re

global count
count = 0
def packet_callback(packet):
    pkt = bytes(packet)
    global count
    IP_PROTO_ICMP = 1
    IP_PROTO_TCP  = 6
    IP_PROTO_UDP  = 17
    IP_PROTO_COMP = 146 ## user defined header
    
    HEADER_LENGTH_ETHERNET = 14
    HEADER_LENGTH_IP       = 20
    HEADER_LENGTH_ICMP     = 8
    HEADER_LENGTH_UDP      = 8
    HEADER_LENGTH_TCP      = 20
    HEADER_LENGTH_COMP     = 14 ## user defined header
    
    print(" ----------------------------------- packet-in -----------------------------------")
    indent = " "
    now_indent = indent
    ## Ethernet header report ## ------------------------
    pre_pos = 0
    end_pos = HEADER_LENGTH_ETHERNET
    eth_report = Ether(pkt[pre_pos:end_pos])
    eth_report.show2()    
    ## IPv4 header report ## ------------------------
    pre_pos = end_pos
    end_pos += HEADER_LENGTH_IP
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
            end_pos += HEADER_LENGTH_COMP
            comp_report = COMP(pkt[pre_pos:end_pos])
            for cnt in range(comp_header_count):
                now_indent += indent
            comp_report.show2(lvl=now_indent)
            compType = comp_report.compType
        ## TCP header report ## ------------------------
        if compType == IP_PROTO_TCP:
            pre_pos = end_pos
            end_pos += HEADER_LENGTH_TCP
            tcp_report = TCP(pkt[pre_pos:end_pos])
            now_indent += indent
            tcp_report.show2(lvl=now_indent)
        elif compType == IP_PROTO_UDP:
            pre_pos = end_pos
            end_pos += HEADER_LENGTH_UDP
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
