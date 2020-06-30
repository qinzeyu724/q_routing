# Q_routing
## qlearning_transit.p4
需要实现的功能有：
- 收到数据包之后，根据目的ip地址寻找最近路径（计划使用crc16算法定位寄存器）
- 往ingress port 返回一个数据包，带自己这边的q_value值
- 在收到返回的数据包之后，更新自己这边的q_value

现在我感觉不如把寄存器的位置在控制平面进行设置，这样可以少好多次crc计算


p4c-bm2-ss --p4v 16 --p4runtime-files build/qlearning_source.p4.p4info.txt -o build/qlearning_source.json qlearning_source.p4
p4c-bm2-ss --p4v 16 --p4runtime-files build/qlearning_transit.p4.p4info.txt -o build/qlearning_transit.json qlearning_transit.p4
p4c-bm2-ss --p4v 16 --p4runtime-files build/qlearning.p4.p4info.txt -o build/qlearning.json qlearning.p4