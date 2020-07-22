#!/usr/bin/env python
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption, bind_layers
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw, Ether
from scapy.fields import *
from scapy.layers.inet import _IPOption_HDR
import numpy as np

from time import time

def get_if():
    ifs=get_if_list()
    iface=None
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                  IntField("qdepth", 0)]
    def extract_padding(self, p):
                return "", p

class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    FieldLenField("length", None, fmt="B",
                                  length_of="swtraces",
                                  adjust=lambda pkt,l:l*2+4),
                    ShortField("count", 0),
                    PacketListField("swtraces",
                                   [],
                                   SwitchTrace,
                                   count_from=lambda pkt:(pkt.count*1)) ]

class qlearning(Packet):
    name = "qlearningpacket"
    fields_desc = [ByteField("hops",0),BitField("EgressPort",0,16),BitField("IngressGlobalTimestamp",0,48),BitField("q_value",0,48)]


bind_layers(IP,qlearning,proto = 143)
bind_layers(qlearning,UDP)
class packet_handle:
    def __init__(self,iface):
        self.q_time = []
        self.iface = iface
        self.packet_count = 0
    def handle_pkt(self, pkt):
        if pkt.haslayer(qlearning):
            ip = pkt.getlayer(IP)
            if ip.src == "10.0.2.2" and ip.dst == "10.0.1.1":
                self.packet_count += 1
                q = pkt.getlayer(qlearning)
                current_time = int(float(time())*1000000)
                # print(pkt.getlayer(Raw))
                previous = int(str(pkt.getlayer(Raw)))
                rtt = current_time-previous
                if len(self.q_time) < 100:
                    self.q_time.append(rtt)
                else:
                    print(np.mean(self.q_time))
                    # print(self.packet_count)
                    self.q_time = []
                    self.q_time.append(rtt)
        sys.stdout.flush()


def main():
    try:
        iface = 'eth0'
        ph = packet_handle(iface)
        print "sniffing on %s" % iface
        sys.stdout.flush()
        packetlist = sniff(iface = iface,prn = ph.handle_pkt)
    except expression as identifier:
        raise
    finally:
        print(ph.packet_count)
if __name__ == '__main__':
    main()
