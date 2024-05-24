/* -*- P4_16 -*- */
#include <core.p4> 
#include <v1model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x800;
const bit<8>  PROTOTYPE_TCP  = 6;
const bit<8>  PROTOTYPE_UDP  = 17;
const bit<8>  PROTOTYPE_COMP = 146; // original



// if MY_ENTRIES equals 100, then N=2.
#define MY_ENTRIES 100

#define MY_PACK 4 // to save 5 tuple
#define MY_TUPPLE 5// Want to compress 4 packets


register<bit<32>>(MY_TUPPLE) tuple_info0;
register<bit<32>>(MY_TUPPLE) tuple_info1;
register<bit<32>>(MY_TUPPLE) tuple_info2;
register<bit<32>>(MY_TUPPLE) tuple_info3;

// to count now packet number
register<bit<32>>(1) now_array;

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
    bit<6>    diffserv;
    bit<2>    priority;
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

header comp_t {
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8>  protocol;
    bit<8>  compType;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

struct metadata {
    bit<6>          table_val;
    ipv4_t          tmp_ipv4;
    /* empty */
}

struct headers {
    ethernet_t            ethernet;
    ipv4_t                ipv4;
    comp_t[MY_PACK]       comp;
    tcp_t                 tcp;
    udp_t                 udp;
}
header comp_data {
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8>  protocol;
    bit<8>  compType;
}
header comp32_t {
    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<32> srcPort;
    bit<32> dstPort;
    bit<32> protocol;
    bit<32> compType;
}
struct comp_value {
    comp32_t[MY_PACK] comp;
}

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
            ETHERTYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            PROTOTYPE_TCP : parse_tcp;
            PROTOTYPE_UDP : parse_udp;
            PROTOTYPE_COMP: parse_comp;
            default: accept;
        }
    }

    state parse_comp {
	    packet.extract(hdr.comp.next);
	    transition select(hdr.comp.last.compType) {
            PROTOTYPE_TCP : parse_tcp;
            PROTOTYPE_UDP : parse_udp;
            PROTOTYPE_COMP: parse_comp;
            default: accept;
	    }
    }

    state parse_tcp {
	    packet.extract(hdr.tcp);
	    transition accept;
    }

    state parse_udp {
	    packet.extract(hdr.udp);
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

    // ==================== used to determin vid
    bit<32> get_position;

    // ==================== processing the usual ipv4
    action drop() {
        mark_to_drop(standard_metadata);
    }
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
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
        default_action = drop();
    }

    register<bit<16>>(100) debug;
    //register<comp_data>(MY_PACK) comp_d;

    apply {
        
        if(hdr.ipv4.isValid() && (hdr.tcp.isValid() || hdr.udp.isValid())){
            bit<32> now_i;
            now_array.read(now_i, 0);
            if (now_i == 0){
                tuple_info0.write(0, hdr.ipv4.srcAddr);
                tuple_info0.write(1, hdr.ipv4.dstAddr);
                tuple_info0.write(4, (bit<32>)hdr.ipv4.protocol);
                if (hdr.tcp.isValid()) {
                    tuple_info0.write(2, (bit<32>)hdr.tcp.srcPort);
                    tuple_info0.write(3, (bit<32>)hdr.tcp.dstPort);
                }
                else if(hdr.udp.isValid()) {
                    tuple_info0.write(2, (bit<32>)hdr.udp.srcPort);
                    tuple_info0.write(3, (bit<32>)hdr.udp.dstPort);
                }
                now_i = now_i + 1;
                now_array.write(0, now_i);
                debug.write(1, 111);
            }
            else if (now_i == 1){
                tuple_info1.write(0, hdr.ipv4.srcAddr);
                tuple_info1.write(1, hdr.ipv4.dstAddr);
                tuple_info1.write(4, (bit<32>)hdr.ipv4.protocol);
                if (hdr.tcp.isValid()) {
                    tuple_info1.write(2, (bit<32>)hdr.tcp.srcPort);
                    tuple_info1.write(3, (bit<32>)hdr.tcp.dstPort);
                }
                else if(hdr.udp.isValid()) {
                    tuple_info1.write(2, (bit<32>)hdr.udp.srcPort);
                    tuple_info1.write(3, (bit<32>)hdr.udp.dstPort);
                }
                now_i = now_i + 1;
                now_array.write(0, now_i);
                debug.write(2, 222);
            }
            else if (now_i == 2){
                tuple_info2.write(0, hdr.ipv4.srcAddr);
                tuple_info2.write(1, hdr.ipv4.dstAddr);
                tuple_info2.write(4, (bit<32>)hdr.ipv4.protocol);
                if (hdr.tcp.isValid()) {
                    tuple_info2.write(2, (bit<32>)hdr.tcp.srcPort);
                    tuple_info2.write(3, (bit<32>)hdr.tcp.dstPort);
                }
                else if(hdr.udp.isValid()) {
                    tuple_info2.write(2, (bit<32>)hdr.udp.srcPort);
                    tuple_info2.write(3, (bit<32>)hdr.udp.dstPort);
                }
                now_i = now_i + 1;
                now_array.write(0, now_i);
                
                debug.write(3, 333);
            }
            else if (now_i == 3){
                tuple_info3.write(0, hdr.ipv4.srcAddr);
                tuple_info3.write(1, hdr.ipv4.dstAddr);
                tuple_info3.write(4, (bit<32>)hdr.ipv4.protocol);
                if (hdr.tcp.isValid()) {
                    tuple_info3.write(2, (bit<32>)hdr.tcp.srcPort);
                    tuple_info3.write(3, (bit<32>)hdr.tcp.dstPort);
                }
                else if(hdr.udp.isValid()) {
                    tuple_info3.write(2, (bit<32>)hdr.udp.srcPort);
                    tuple_info3.write(3, (bit<32>)hdr.udp.dstPort);
                }
                now_i = now_i + 1;
                now_array.write(0, now_i);
                
                debug.write(4, 444);
            }
            if (now_i >= MY_PACK && !hdr.comp[0].isValid()) {
                comp_value c;
                
                // Get each value
                tuple_info0.read(c.comp[0].srcAddr,  0);
                tuple_info0.read(c.comp[0].dstAddr,  1);
                tuple_info0.read(c.comp[0].srcPort,  2);
                tuple_info0.read(c.comp[0].dstPort,  3);
                tuple_info0.read(c.comp[0].protocol, 4);
                
                tuple_info1.read(c.comp[1].srcAddr,  0);
                tuple_info1.read(c.comp[1].dstAddr,  1);
                tuple_info1.read(c.comp[1].srcPort,  2);
                tuple_info1.read(c.comp[1].dstPort,  3);
                tuple_info1.read(c.comp[1].protocol, 4);
                
                tuple_info2.read(c.comp[2].srcAddr,  0);
                tuple_info2.read(c.comp[2].dstAddr,  1);
                tuple_info2.read(c.comp[2].srcPort,  2);
                tuple_info2.read(c.comp[2].dstPort,  3);
                tuple_info2.read(c.comp[2].protocol, 4);
                
                tuple_info3.read(c.comp[3].srcAddr,  0);
                tuple_info3.read(c.comp[3].dstAddr,  1);
                tuple_info3.read(c.comp[3].srcPort,  2);
                tuple_info3.read(c.comp[3].dstPort,  3);
                tuple_info3.read(c.comp[3].protocol, 4);

                hdr.comp[0].setValid();
		        hdr.comp[1].setValid();
		        hdr.comp[2].setValid();
		        hdr.comp[3].setValid();
                
                hdr.comp[0].srcAddr  = c.comp[0].srcAddr;
                hdr.comp[0].dstAddr  = c.comp[0].dstAddr;
                hdr.comp[0].srcPort  = (bit<16>)c.comp[0].srcPort;
                hdr.comp[0].dstPort  = (bit<16>)c.comp[0].dstPort;
                hdr.comp[0].protocol = (bit<8>)c.comp[0].protocol;
                hdr.comp[0].compType = PROTOTYPE_COMP;
                
                
                hdr.comp[1].srcAddr  = c.comp[1].srcAddr;
                hdr.comp[1].dstAddr  = c.comp[1].dstAddr;
                hdr.comp[1].srcPort  = (bit<16>)c.comp[1].srcPort;
                hdr.comp[1].dstPort  = (bit<16>)c.comp[1].dstPort;
                hdr.comp[1].protocol = (bit<8>) c.comp[1].protocol;
                hdr.comp[1].compType = PROTOTYPE_COMP;
                
                hdr.comp[2].srcAddr  = c.comp[2].srcAddr;
                hdr.comp[2].dstAddr  = c.comp[2].dstAddr;
                hdr.comp[2].srcPort  = (bit<16>)c.comp[2].srcPort;
                hdr.comp[2].dstPort  = (bit<16>)c.comp[2].dstPort;
                hdr.comp[2].protocol = (bit<8>) c.comp[2].protocol;
                hdr.comp[2].compType = PROTOTYPE_COMP;
                
                hdr.comp[3].srcAddr  = c.comp[3].srcAddr;
                hdr.comp[3].dstAddr  = c.comp[3].dstAddr;
                hdr.comp[3].srcPort  = (bit<16>)c.comp[3].srcPort;
                hdr.comp[3].dstPort  = (bit<16>)c.comp[3].dstPort;
                hdr.comp[3].protocol = (bit<8>) c.comp[3].protocol;
		        hdr.comp[3].compType = hdr.ipv4.protocol;
		        hdr.ipv4.protocol = PROTOTYPE_COMP;
                now_i = 0;
                now_array.write(0, now_i);
                
                debug.write(10, (bit<16>)c.comp[0].protocol);
                debug.write(11, (bit<16>)hdr.comp[0].compType);
                debug.write(12, (bit<16>)PROTOTYPE_COMP);
                
                debug.write(14, (bit<16>)c.comp[1].protocol);
                debug.write(15, (bit<16>)hdr.comp[1].compType);
                
                debug.write(17, (bit<16>)c.comp[2].protocol);
                debug.write(18, (bit<16>)hdr.comp[2].compType);
                
                debug.write(20, (bit<16>)c.comp[3].protocol);
                debug.write(21, (bit<16>)hdr.comp[3].compType);

                /*
                tuple_info0.write(0, 0);
                tuple_info0.write(1, 0);
                tuple_info0.write(2, 0);
                tuple_info0.write(3, 0);
                tuple_info0.write(4, 0);

                tuple_info1.write(0, 0);
                tuple_info1.write(1, 0);
                tuple_info1.write(2, 0);
                tuple_info1.write(3, 0);
                tuple_info1.write(4, 0);

                tuple_info2.write(0, 0);
                tuple_info2.write(1, 0);
                tuple_info2.write(2, 0);
                tuple_info2.write(3, 0);
                tuple_info2.write(4, 0);

                tuple_info3.write(0, 0);
                tuple_info3.write(1, 0);
                tuple_info3.write(2, 0);
                tuple_info3.write(3, 0);
                tuple_info3.write(4, 0);
                */
            }
            
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
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
    apply {

	    update_checksum(
	        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
	            hdr.ipv4.ihl,
		        hdr.ipv4.diffserv,
		        hdr.ipv4.priority,
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
        packet.emit(hdr.comp);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
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
