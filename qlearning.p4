/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  Q_PROTOCOL_SOURCE = 0x8F;
const bit<8>  Q_PROTOCOL_SINK = 0x90;
const bit<8> Q_PROTOCOL_BACK = 0x91;
const bit<32> PKT_INSTANCE_TYPE_NORMAL = 0;
const bit<32> PKT_INSTANCE_TYPE_INGRESS_CLONE = 1;
const bit<32> PKT_INSTANCE_TYPE_EGRESS_CLONE = 2;
const bit<32> PKT_INSTANCE_TYPE_COALESCED = 3;
const bit<32> PKT_INSTANCE_TYPE_INGRESS_RECIRC = 4;
const bit<32> PKT_INSTANCE_TYPE_REPLICATION = 5;
const bit<32> PKT_INSTANCE_TYPE_RESUBMIT= 6;


/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<8> port_number_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header q_learning_t {
    // mark the egress port and the timestamp when the packet is enqueued.
    bit<16> egress_port;
    bit<48> ingress_global_timestamp;
    // 没有实际意义，唯一作用在于clone操作中传递信息
    bit<48> q_value;
}

header q_back_t{
    bit<16> egress_port;
    bit<48> ingress_global_timestamp;
    bit<48> q_value;
}

struct q_flag_metadata_t{
    bit<8> flag;
}

struct metadata {
     bit<8> active_port;
     bit<48> q_value;
}

struct headers {
    ethernet_t          ethernet;
    ipv4_t                   ipv4;
    q_learning_t     q_header;
    q_back_t            q_back;
}

error { IPHeaderTooShort }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        verify(hdr.ipv4.ihl >= 5, error.IPHeaderTooShort);
        transition select(hdr.ipv4.protocol){
            Q_PROTOCOL_SOURCE: parse_q_header;
            Q_PROTOCOL_BACK: parse_q_back;
            default: accept;
        }

    }

    state parse_q_header{
        packet.extract(hdr.q_header);
        transition accept;
    }

    state parse_q_back{
        packet.extract(hdr.q_back);
        transition accept;
    }
  
}


/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {   
    apply {  }
}


/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    
    register<bit<48>>(16) q_value;
    register<bit<4>>(1) packet_count;
    register<bit<16>>(16) port_count;
    register<bit<1>>(8) port_active_test;
    bit<4> count_temp;
    bit<4> count_temp2;
    bit<16> count_temp3;
    bit<48> q_value_temp;
    bit<48> q_value_temp1;
    bit<48> q_value_temp2;
    bit<48> reward;
    
    // 对应8个端口
    bit<48> q1;
    bit<48> q2;
    bit<48> q3;
    bit<48> q4;
    bit<48> q5;
    bit<48> q6;
    bit<48> q7;
    bit<48> q8;
    bit<48> min_q = 0xFFFFFFFFFFFF;
    bit<9> min_port = 0;
    action ipv4_clone(){
        clone(CloneType.I2E,(bit<32>)standard_metadata.ingress_port);
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action read_q8(){
        q_value.read(q8,(bit<32>)8);
        if(meta.active_port[0:0]==1){
            if(q8 < min_q){
                min_q = q8;
                min_port = 8;
            }
        }
        meta.q_value = min_q;
    } 
    action read_q7(){
        q_value.read(q7,(bit<32>)7);
        if(meta.active_port[1:1]==1){
            if(q7 < min_q){
                min_q = q7;
                min_port = 7;
            }
        }    
        read_q8();
    }
    action read_q6(){
        q_value.read(q6,(bit<32>)6);
        if(meta.active_port[2:2]==1){
            if(q6 < min_q){
                min_q = q6;
                min_port = 6;
            }
        }
        read_q7();
    }
    action read_q5(){
        q_value.read(q5,(bit<32>)5);
        if(meta.active_port[3:3]==1){
            if(q5 < min_q){
                min_q = q5;
                min_port = 5;
            }
        }
        read_q6();
    }
    action read_q4(){
        q_value.read(q4,(bit<32>)4);
        if(meta.active_port[4:4]==1){
            if(q4 < min_q){
                min_q = q4;
                min_port = 4;
            }
        }
        read_q5();
    }
    action read_q3(){
        q_value.read(q3,(bit<32>)3);
        if(meta.active_port[5:5]==1){
            if(q3 < min_q){
                min_q = q3;
                min_port = 3;
            }
        }
        read_q4();
    }
    action read_q2(){
        q_value.read(q2,(bit<32>)2);
        if(meta.active_port[6:6]==1){
            if(q2 < min_q){
                min_q = q2;
                min_port = 2;
            }
        }
        read_q3();
    }
    action read_q1(){
        q_value.read(q1,(bit<32>)1);
        if(meta.active_port[7:7]==1){
            if(q1 < min_q){
                min_q = q1;
                min_port = 1;
            }
        }
        read_q2();
    }
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action minimum_delay_forward(){
        packet_count.read(count_temp,(bit<32>)0);
        read_q1();
        if(count_temp == 1 && meta.active_port[7:7]==1){
            standard_metadata.egress_spec = 9w1;
            meta.q_value = q1;
        }else if(count_temp == 2 && meta.active_port[6:6]==1){
            standard_metadata.egress_spec = 9w2;
            meta.q_value = q2;
        }else if(count_temp == 3 && meta.active_port[5:5]==1){
            standard_metadata.egress_spec = 9w3;
            meta.q_value = q3;
        }else if(count_temp == 4 && meta.active_port[4:4]==1){
            standard_metadata.egress_spec = 9w4;
            meta.q_value = q4;
        }else if(count_temp == 5 && meta.active_port[3:3]==1){
            standard_metadata.egress_spec = 9w5;
            meta.q_value = q5;
        }else if(count_temp == 6 && meta.active_port[2:2]==1){
            standard_metadata.egress_spec = 9w6;
            meta.q_value = q6;
        }else if(count_temp == 7 && meta.active_port[1:1]==1){
            standard_metadata.egress_spec = 9w7;
            meta.q_value = q7;
        }else if(count_temp == 8 && meta.active_port[0:0]==1){
            standard_metadata.egress_spec = 9w8;
            meta.q_value = q8;
        }else{
            standard_metadata.egress_spec = min_port;
            meta.q_value = min_q;
        }
        count_temp = count_temp + 1;
        packet_count.write((bit<32>)0,count_temp);
        port_count.read(count_temp3,(bit<32>)standard_metadata.egress_spec);
        count_temp3 = count_temp3+1;
        port_count.write((bit<32>)standard_metadata.egress_spec,count_temp3);
        // ipv4_clone();
    }
    table ipv4_qlearning {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
            minimum_delay_forward;
        }
        size = 1024;
        default_action = NoAction();
    }
    action get_active_port(port_number_t port_number){
        meta.active_port = port_number;
        port_active_test.write((bit<32>)7,meta.active_port[0:0]);
        port_active_test.write((bit<32>)6,meta.active_port[1:1]);
        port_active_test.write((bit<32>)5,meta.active_port[2:2]);
        port_active_test.write((bit<32>)4,meta.active_port[3:3]);
        port_active_test.write((bit<32>)3,meta.active_port[4:4]);
        port_active_test.write((bit<32>)2,meta.active_port[5:5]);
        port_active_test.write((bit<32>)1,meta.active_port[6:6]);
        port_active_test.write((bit<32>)0,meta.active_port[7:7]);
    }
    table qlearning_active_ports {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            get_active_port;
            ipv4_forward;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }
    apply {
        qlearning_active_ports.apply();
        if(hdr.q_back.isValid()){
            // 需要根据返回的数据包更新自己的q值
            reward = standard_metadata.ingress_global_timestamp - hdr.q_back.ingress_global_timestamp;
            // 除以2,相当于单程delay
            reward = reward >> 1;
            reward = reward + hdr.q_back.q_value;
            reward = reward >> 2;
            q_value.read(q_value_temp,(bit<32>)hdr.q_header.egress_port);
            q_value_temp1 = q_value_temp >> 1;
            q_value_temp2 = q_value_temp >> 2;
            q_value_temp = q_value_temp1 + q_value_temp2 + reward;
            q_value.write((bit<32>)hdr.q_header.egress_port,q_value_temp);
            mark_to_drop(standard_metadata);
        }
        else if (hdr.q_header.isValid()) {
            // 假如这个包头中q_header已经存在
            ipv4_qlearning.apply();
            hdr.q_header.q_value = meta. q_value;
            ipv4_clone();
        }else if (hdr.ipv4.isValid()){
            hdr.ipv4.protocol = Q_PROTOCOL_SOURCE;
            minimum_delay_forward();
        }else{
            mark_to_drop(standard_metadata);
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply {
        if (standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
                // 将q_header更改为q_back
                hdr.q_back.setValid();
                hdr.q_back.egress_port = hdr.q_header.egress_port;
                hdr.q_back.ingress_global_timestamp = hdr.q_header.ingress_global_timestamp;
                hdr.q_back.q_value = hdr.q_header.q_value;
                hdr.ipv4.protocol = Q_PROTOCOL_BACK;
                hdr.q_header.setInvalid();
        }else if(hdr.q_header.isValid()){
            hdr.q_header.egress_port = 7w0 ++ standard_metadata.egress_port;
            hdr.q_header.ingress_global_timestamp = standard_metadata.ingress_global_timestamp;
            hdr.q_header.q_value = 0;    
        }else if (hdr.ipv4.protocol == Q_PROTOCOL_SOURCE){
            hdr.q_header.setValid();
            // could also be egress_spec
            hdr.q_header.egress_port = 7w0 ++ standard_metadata.egress_port;
            hdr.q_header.ingress_global_timestamp = standard_metadata.ingress_global_timestamp;
            hdr.q_header.q_value = 0;
            hdr.ipv4.totalLen = hdr.ipv4.totalLen + 14;
        }
    }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers hdr, inout metadata meta) {
     apply {
	update_checksum(
	    hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	          hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.q_header);       
        packet.emit(hdr.q_back);     
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;