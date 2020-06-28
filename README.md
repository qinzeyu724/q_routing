# Q_routing
## qlearning_transit.p4
需要实现的功能有：
- 收到数据包之后，根据目的ip地址寻找最近路径（计划使用crc16算法定位寄存器）
- 往ingress port 返回一个数据包，带自己这边的q_value值
- 在收到返回的数据包之后，更新自己这边的q_value
