#!/usr/bin/env python3
import random
import demjson
import json
host_num = 2
sw_num = 16

topology = {}
host = {}
sw ={}
link = []

for i in range(1,host_num+1):
    hi = 'h'+str(i)
    host[hi] = {}
    host[hi]['ip'] = "10.0.{}.{}/24".format(i,i)
    host[hi]['mac'] = "08:00:00:00:0{}:{}{}".format(i,i,i)
    host[hi]['commands'] = ["route add default gw 10.0.{}.{}0 dev eth0".format(i,i),"arp -i eth0 -s 10.0.{}.{}0 08:00:00:00:0{}:00".format(i,i,i) ]

for i in range(1,sw_num+1):
    si = "s"+str(i)
    sw[si] = {}
    sw[si]["runtime_json"] = "s{}-runtime.json".format(i)


link = [["h1", "s1-p1"], ["s1-p2", "s2-p1"], ["s1-p3", "s5-p1"],["s2-p2", "s3-p1"], ["s2-p3", "s6-p1"], ["s3-p2", "s4-p1"],
["s3-p3", "s7-p1"],["s4-p2", "s8-p1"],["s5-p2", "s6-p2"],["s5-p3", "s9-p1"],["s6-p3", "s7-p2"],["s6-p4", "s10-p1"],["s7-p3", "s8-p2"],
["s7-p4", "s11-p1"],["s8-p3", "s12-p1"],["s9-p2", "s10-p2"],["s9-p3", "s13-p1"],["s10-p3", "s11-p2"],["s10-p4", "s14-p1"],["s11-p3", "s12-p2"]
,["s11-p4","s15-p1"],["s12-p3", "s16-p1"],["s13-p2", "s14-p2"],["s14-p3", "s15-p2"],["s15-p3", "s16-p2"],["s16-p3", "h2"]]

topology["hosts"] = host
topology['switches']  = sw
topology['links'] = link

for i in range(2,sw_num):
    file_name = "s{}-runtime.json".format(i)

# short_link = [["s1-p3","s5-p1"],["s5-p3","s9-p1"],["s9-p3","s13-p1"],["s13-p2","s14-p2"],["s14-p3","s15-p2"],["s15-p3","s16-p2"]]
short_link = []
for x in link:
    if x in short_link:
        x.append("5ms")
    else:
        x.append("{}ms".format(random.randint(10,100)))


f=open('random_topology.json', 'w+')
print (json.dumps(topology, sort_keys=True, indent=4, separators=(',', ': ')),file = f)


