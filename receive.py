#!/usr/bin/env python
import sys
import struct

from scapy.all import sniff, sendp, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption, bind_layers
from scapy.all import PacketListField, ShortField, IntField, LongField, BitField, FieldListField, FieldLenField
from scapy.all import IP, UDP, Raw
from scapy.fields import *
from scapy.layers.inet import _IPOption_HDR
import numpy as np

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
    fields_desc = [ByteField("hops",0)]


bind_layers(IP,qlearning,proto = 143)
class packet_handle:
    def __init__(self):
        self.q_hops = []
    def handle_pkt(self, pkt):
        if pkt.haslayer(qlearning):
            q = pkt.getlayer(qlearning)
            if len(self.q_hops) < 100:
                self.q_hops.append(q.hops)
            else:
                print(np.mean(self.q_hops))
                self.q_hops = []
        sys.stdout.flush()


def main():
    ph = packet_handle()
    iface = 'eth0'
    print "sniffing on %s" % iface
    sys.stdout.flush()
    packetlist = sniff(iface = iface,prn = ph.handle_pkt)
if __name__ == '__main__':
    main()
