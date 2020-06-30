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
            Q_PROTOCOL_SINK: parse_q_header;
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
    
    register<bit<48>>(8) q_value;
    register<bit<4>>(1) packet_count;
    register<bit<16>>(8) port_count;


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
    bit<9> min_port = 1;

    action read_q8(){
        q_value.read(q8,(bit<32>)8);
        if(meta.active_port[6:6]==0x1){
            if(q8 < min_q){
                min_q = q8;
                min_port = 8;
            }
        }
    } 
    action read_q7(){
        q_value.read(q7,(bit<32>)7);
        if(meta.active_port[6:6]==0x1){
            if(q7 < min_q){
                min_q = q7;
                min_port = 7;
            }
        }    
        read_q8();
    }
    action read_q6(){
        q_value.read(q6,(bit<32>)6);
        if(meta.active_port[5:5]==0x1){
            if(q6 < min_q){
                min_q = q6;
                min_port = 6;
            }
        }
        read_q7();
    }
    action read_q5(){
        q_value.read(q5,(bit<32>)5);
        if(meta.active_port[4:4]==0x1){
            if(q5 < min_q){
                min_q = q5;
                min_port = 5;
            }
        }
        read_q6();
    }
    action read_q4(){
        q_value.read(q4,(bit<32>)4);
        if(meta.active_port[3:3]==0x1){
            if(q4 < min_q){
                min_q = q4;
                min_port = 4;
            }
        }
        read_q5();
    }
    action read_q3(){
        q_value.read(q3,(bit<32>)3);
        if(meta.active_port[2:2]==0x1){
            if(q3 < min_q){
                min_q = q3;
                min_port = 3;
            }
        }
        read_q4();
    }
    action read_q2(){
        q_value.read(q2,(bit<32>)2);
        if(meta.active_port[1:1]==0x1){
            if(q2 < min_q){
                min_q = q2;
                min_port = 2;
            }
        }
        read_q3();
    }
    action read_q1(){
        q_value.read(q1,(bit<32>)1);
        if(meta.active_port[0:0]==0x1){
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

    action get_active_port(bit<8> port_number){
        meta.active_port = port_number;
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    action minimum_delay_forward(){
        packet_count.read(count_temp,(bit<32>)0);
        read_q1();
        if(count_temp == 2 && meta.active_port[1:1]==1){
            standard_metadata.egress_spec = 9w2;
        }else if(count_temp == 3 && meta.active_port[2:2]==1){
            standard_metadata.egress_spec = 9w3;
        }else if(count_temp == 4 && meta.active_port[3:3]==1){
            standard_metadata.egress_spec = 9w4;
        }else if(count_temp == 5 && meta.active_port[4:4]==1){
            standard_metadata.egress_spec = 9w5;
        }else if(count_temp == 6 && meta.active_port[5:5]==1){
            standard_metadata.egress_spec = 9w6;
        }else if(count_temp == 7 && meta.active_port[6:6]==1){
            standard_metadata.egress_spec = 9w7;
        }else if(count_temp == 8 && meta.active_port[7:7]==1){
            standard_metadata.egress_spec = 9w8;
        }else{
            standard_metadata.egress_spec = min_port;
        }
        count_temp = count_temp + 1;
        packet_count.write((bit<32>)0,count_temp);
        port_count.read(count_temp3,(bit<32>)standard_metadata.egress_spec);
        count_temp3 = count_temp3+1;
        port_count.write((bit<32>)standard_metadata.egress_spec,count_temp3);
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
    table qlearning_active_ports {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            get_active_port;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }


    
    apply {
        if(hdr.q_back.isValid()){
            qlearning_active_ports.apply();
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
        else if (hdr.ipv4.isValid()) {
            ipv4_qlearning.apply();
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
        if (hdr.ipv4.protocol == Q_PROTOCOL_SOURCE){
            hdr.q_header.setValid();
            // could also be egress_spec
            hdr.q_header.egress_port = 7w0 ++ standard_metadata.egress_port;
            hdr.q_header.ingress_global_timestamp = standard_metadata.ingress_global_timestamp;
            hdr.q_header.q_value = 0;
            hdr.ipv4.totalLen = hdr.ipv4.totalLen + 6;
        }
        if (hdr.ipv4.protocol == Q_PROTOCOL_SINK){
            hdr.q_header.setInvalid();
            hdr.ipv4.totalLen = hdr.ipv4.totalLen - 6;
            hdr.ipv4.protocol = UDP_PROTOCOL;
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