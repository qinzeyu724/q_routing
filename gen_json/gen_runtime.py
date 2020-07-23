#!/usr/bin/env python3
import random
import demjson
import json
class TableEntry:
    def __init__(self,table,match,action_name,action_params = None):
        self.table = table
        self.match = match
        self.action_name = action_name
        if action_params:
            self.action_params = action_params
        else:
            self.action_params = {}

port_number = [3,3,3,2,3,4,4,3,3,4,4,3,2,3,3,3]
binarymap = ["0","1","2","3","4","5","6","7","8","9","a","b","c","d","e","f"]
for i in range(1,len(port_number)-1):
    runtime = {}
    runtime["target"] = "bmv2"
    runtime["p4info"] = "build/qlearning.p4.p4info.txt"
    runtime["bmv2_json"] = "build/qlearning.json"

    table_entries = []
    table_entry = {}
    table_entry1 = {}
    table_entry2 = {}
    table_entry3 = {}
    table_entry['table'] = "MyIngress.ipv4_qlearning"
    table_entry['match'] = {"hdr.ipv4.dstAddr":["10.0.2.0",24]}
    table_entry['action_name'] = "MyIngress.minimum_delay_forward"
    table_entry['action_params'] = {}
    table_entry1['table'] = "MyIngress.qlearning_active_ports"
    table_entry1['match'] = {"hdr.ipv4.dstAddr":["10.0.2.0",24]}
    table_entry1['action_name'] = "MyIngress.get_active_port"
    action_params = {}
    action_params["port_number"] = int("1"*port_number[i]+"0"*(8-port_number[i]),2)
    table_entry1['action_params'] = action_params
    tbet2 = TableEntry(table="MyIngress.ipv4_qlearning",match = {"hdr.ipv4.dstAddr":["10.0.1.0",24]},action_name="MyIngress.minimum_delay_forward")
    tbet3 = TableEntry(table="MyIngress.qlearning_active_ports",match = {"hdr.ipv4.dstAddr":["10.0.1.0",24]},action_name="MyIngress.get_active_port")
    tbet3.action_params["port_number"] = int("1"*port_number[i]+"0"*(8-port_number[i]),2)
    table_entries.append(table_entry)
    table_entries.append(table_entry1)
    table_entries.append(tbet2.__dict__)
    table_entries.append(tbet3.__dict__)
    runtime["table_entries"] = table_entries

    file_name = "s{}-runtime.json".format(i+1)
    f=open(file_name, 'w+')
    print (json.dumps(runtime, sort_keys=True, indent=4, separators=(',', ': ')),file = f)
