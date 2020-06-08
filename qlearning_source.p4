/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<8>  UDP_PROTOCOL = 0x11;
const bit<16> TYPE_IPV4 = 0x800;
const bit<5>  IPV4_OPTION_MRI = 31;
const bit<8>  Q_PROTOCOL_SOURCE = 0x8F;
const bit<8>  Q_PROTOCOL_SINK = 0x90;

#define MAX_HOPS 9

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;
typedef bit<32> switchID_t;
typedef bit<32> qdepth_t;

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
}


header switch_t {
    switchID_t  swid;
    qdepth_t    qdepth;
}

struct ingress_metadata_t {
    bit<16>  count;
}

struct parser_metadata_t {
    bit<16>  remaining;
}

struct q_flag_metadata_t{
    bit<8> flag;
}

struct metadata {
    q_flag_metadata_t q_flag_metadata;
}

struct headers {
    ethernet_t         ethernet;
    ipv4_t             ipv4;
    q_learning_t       q_header;
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
            default: accept;
        }

    }

    state parse_q_header{
        packet.extract(hdr.q_header);
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
    register<bit<48>>(64) ingress_global_timestamp;
    register<bit<48>>(64) ret_timestamp;
    register<bit<48>>(64) time;
    register<bit<48>>(64) reward_array;

    bit<4> count_temp;
    bit<4> count_temp2;
    bit<48> q_value_temp;
    bit<48> q_value_temp1;
    bit<48> q_value_temp2;
    bit<48> reward;
    bit<48> q2;
    bit<48> q3;
    bit<48> q4;

    action drop() {
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action minimum_delay_forward(){
        packet_count.read(count_temp,(bit<32>)0);
        q_value.read(q2,(bit<32>)2);
        q_value.read(q3,(bit<32>)3);
        q_value.read(q4,(bit<32>)4);
        if(count_temp == 2){
            standard_metadata.egress_spec = 9w2;
        }else if(count_temp == 3){
            standard_metadata.egress_spec = 9w3;
        }else if(count_temp == 4){
            standard_metadata.egress_spec = 9w4;
        }else{
            if((q2<q3)&&(q2<q4)){
                standard_metadata.egress_spec = 9w2;
            }else if((q3<q2)&&(q3<q4)){
                standard_metadata.egress_spec = 9w3;
            }else{
                standard_metadata.egress_spec = 9w4;
            }
        }
        count_temp = count_temp + 1;
        packet_count.write((bit<32>)0,count_temp);

    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
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
    }


    
    apply {
        if (hdr.q_header.isValid()){
            packet_count.read(count_temp2,(bit<32>)0);
            ingress_global_timestamp.write((bit<32>)count_temp2, hdr.q_header.ingress_global_timestamp);
            ret_timestamp.write((bit<32>)count_temp2, standard_metadata.ingress_global_timestamp);
            reward = standard_metadata.ingress_global_timestamp - hdr.q_header.ingress_global_timestamp;
            time.write((bit<32>)count_temp2, reward);
            reward = reward >> 2;
            reward_array.write((bit<32>)count_temp2, reward);
            q_value.read(q_value_temp,(bit<32>)hdr.q_header.egress_port);
            q_value_temp1 = q_value_temp >> 1;
            q_value_temp2 = q_value_temp >> 2;
            q_value_temp = q_value_temp1 + q_value_temp2 + reward;
            q_value.write((bit<32>)hdr.q_header.egress_port,q_value_temp);
            // compute
        }
        if (hdr.ipv4.isValid()) {
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
