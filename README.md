# Q_routing
## qlearning_transit.p4
目前已经实现的功能有：

- 根据Q值查找最优路径
- 根据返回的clone packet更新Q值

还需要完善的功能有：

- bmv2中没有生成包的功能，需要自己写一个extern
- 没有考虑hash值冲突的情况
- 对比实验没有完善

代码放在tutorial/exercise文件夹下，执行时与exercise的步骤相同
p4c-bm2-ss --p4v 16 --p4runtime-files build/qlearning.p4.p4info.txt -o build/qlearning.json qlearning.p4