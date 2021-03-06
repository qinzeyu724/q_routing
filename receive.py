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
    def __init__(self,iface,fo):
        self.q_hops = []
        self.iface = iface
        self.fo = fo
        self.packet_count = 0
    def handle_pkt(self, pkt):
        if pkt.haslayer(qlearning):
            q = pkt.getlayer(qlearning)
            ip = pkt.getlayer(IP)
            if ip.src == "10.0.1.1" and ip.dst == "10.0.2.2":
                if len(self.q_hops) < 100:
                    self.q_hops.append(q.hops)
                else:
                    print(np.mean(self.q_hops))
                    self.fo.write(str(np.mean(self.q_hops)))
                    self.fo.write('\n')
                    self.q_hops = []
                    self.q_hops.append(q.hops)
                return_pkt = Ether(src=get_if_hwaddr(self.iface), dst="ff:ff:ff:ff:ff:ff") / IP(dst=pkt.getlayer(IP).src) / UDP(dport=4321, sport=1234) / pkt.getlayer(Raw)
                return_pkt.show2()
                sendp(return_pkt, iface=self.iface)
                self.packet_count +=1
        sys.stdout.flush()


def main():
    try:
        iface = 'eth0'
        fo = open('hops.txt',"wb")
        ph = packet_handle(iface,fo)
        print "sniffing on %s" % iface
        sys.stdout.flush()
        packetlist = sniff(iface = iface,prn = ph.handle_pkt)
    except KeyboardInterrupt:
        raise
    finally:
        fo.close()
        print(ph.packet_count)
if __name__ == '__main__':
    main()
