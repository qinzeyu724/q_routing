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
    bit<32> enq_timestamp;
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
    macAddr_t srcMACAddr;
    ip4Addr_t srcIPAddr;
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
            Q_PROTOCOL_SOURCE: parse_q_header;
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
    action drop() {
        mark_to_drop(standard_metadata);
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }


    action ipv4_sendback(){
        standard_metadata.egress_spec = standard_metadata.ingress_port;
        meta.srcMACAddr = hdr.ethernet.srcAddr;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = meta.srcMACAddr;
        meta.srcIPAddr = hdr.ipv4.srcAddr;
        hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
        hdr.ipv4.dstAddr = meta.srcIPAddr;
        hdr.ipv4.protocol = Q_PROTOCOL_SINK;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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

     action ipv4_clone(){
        clone(CloneType.I2E,(bit<32>)standard_metadata.ingress_port);
    }
    
    apply {
        if (hdr.ipv4.protocol == Q_PROTOCOL_SOURCE){
            ipv4_clone();
        }
        ipv4_lpm.apply();
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {

    apply { 
        // 在这里进行数据包头的处理
        if(standard_metadata.instance_type == PKT_INSTANCE_TYPE_INGRESS_CLONE){
                standard_metadata.egress_spec = standard_metadata.ingress_port;
                meta.srcMACAddr = hdr.ethernet.srcAddr;
                hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
                hdr.ethernet.dstAddr = meta.srcMACAddr;
                meta.srcIPAddr = hdr.ipv4.srcAddr;
                hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
                hdr.ipv4.dstAddr = meta.srcIPAddr;
                hdr.ipv4.protocol = Q_PROTOCOL_SINK;
                hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
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
