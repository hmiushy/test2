/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<8>  TYPE_TCP  = 6;
const bit<16> TYPE_COMP = 0x1212;

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



header comp_t {

    bit<32> srcAddr;
    bit<32> dstAddr;
    bit<16> srcPort;
    bit<16> dstPort;
    bit<8>  protocol;
    bit<16> compType;
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
    comp_t[MY_PACK]       comp;
    ipv4_t                ipv4;
    tcp_t                 tcp;
    udp_t                 udp;
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
            TYPE_IPV4: parse_ipv4;
            TYPE_COMP: parse_comp;
            default: accept;
        }
    }

    state parse_comp {
	    packet.extract(hdr.comp.next);
	    transition select(hdr.comp.last.compType) {
          0: parse_comp;
            TYPE_IPV4: parse_ipv4;
            default: accept;
	}
    }
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol){
            6: parse_tcp;
            17: parse_udp;
            //146: parse_comp;
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



    apply {

        if (hdr.ipv4.isValid()) {

            if (!hdr.comp[0].isValid()) {

		//meta.tmp_ipv4 = hdr.ipv4;
		hdr.comp[0].setValid();
		hdr.comp[1].setValid();
		hdr.comp[2].setValid();
		hdr.comp[3].setValid();
    hdr.comp[0].compType      = 0;
    hdr.comp[1].compType      = 0;
    hdr.comp[2].compType      = 0;
		hdr.comp[3].compType      = hdr.ethernet.etherType;

/*
		hdr.comp[0].setValid();
		hdr.comp[0].compType      = hdr.ethernet.etherType;
    */
		hdr.ethernet.etherType = TYPE_COMP;
            }

            bit<32> now_i;
            now_array.read(now_i, 0);

            if (now_i == 0){
                tuple_info0.write(0, hdr.ipv4.srcAddr);
                tuple_info0.write(1, hdr.ipv4.dstAddr);
                tuple_info0.write(4, (bit<32>)hdr.ipv4.protocol);
                if (hdr.tcp.isValid()) {
                    tuple_info0.write(2, (bit<32>)hdr.udp.srcPort);
                    tuple_info0.write(3, (bit<32>)hdr.udp.dstPort);
                }
                else if(hdr.udp.isValid()) {
                    tuple_info0.write(2, (bit<32>)hdr.tcp.srcPort);
                    tuple_info0.write(3, (bit<32>)hdr.tcp.dstPort);
                }
                now_i = now_i + 1;
                now_array.write(0, now_i);

                bit<32> value;
                tuple_info0.read(value, 0);
                hdr.comp[0].srcAddr = value;

                bit<32> value1;
                tuple_info0.read(value1, 1);
                hdr.comp[0].dstAddr = value1;

                bit<32> value2;
                tuple_info0.read(value2, 2);
                hdr.comp[0].srcPort = (bit<16>)value2;

                bit<32> value3;
                tuple_info0.read(value3, 3);
                hdr.comp[0].dstPort = (bit<16>)value3;

                bit<32> value4;
                tuple_info0.read(value4, 4);
                hdr.comp[0].protocol = (bit<8>)value4;

            }


            else if (now_i == 1){


                tuple_info1.write(0, hdr.ipv4.srcAddr);
                tuple_info1.write(1, hdr.ipv4.dstAddr);
                tuple_info1.write(4, (bit<32>)hdr.ipv4.protocol);
                if (hdr.tcp.isValid()) {
                    tuple_info1.write(2, (bit<32>)hdr.udp.srcPort);
                    tuple_info1.write(3, (bit<32>)hdr.udp.dstPort);
                }
                else if(hdr.udp.isValid()) {
                    tuple_info1.write(2, (bit<32>)hdr.tcp.srcPort);
                    tuple_info1.write(3, (bit<32>)hdr.tcp.dstPort);
                }
                now_i = now_i + 1;
                now_array.write(0, now_i);

                bit<32> value;
                tuple_info0.read(value, 0);
                hdr.comp[0].srcAddr = value;

                bit<32> value1;
                tuple_info0.read(value1, 1);
                hdr.comp[0].dstAddr = value1;

                bit<32> value2;
                tuple_info0.read(value2, 2);
                hdr.comp[0].srcPort = (bit<16>)value2;

                bit<32> value3;
                tuple_info0.read(value3, 3);
                hdr.comp[0].dstPort = (bit<16>)value3;

                bit<32> value4;
                tuple_info0.read(value4, 4);
                hdr.comp[0].protocol = (bit<8>)value4;

                bit<32> value10;
                tuple_info1.read(value10, 0);
                hdr.comp[1].srcAddr = value10;

                bit<32> value11;
                tuple_info1.read(value11, 1);
                hdr.comp[1].dstAddr = value11;

                bit<32> value12;
                tuple_info1.read(value12, 2);
                hdr.comp[1].srcPort = (bit<16>)value12;

                bit<32> value13;
                tuple_info1.read(value13, 3);
                hdr.comp[1].dstPort = (bit<16>)value13;

                bit<32> value14;
                tuple_info1.read(value14, 4);
                hdr.comp[1].protocol = (bit<8>)value14;
            }


            else if (now_i == 2){


                tuple_info2.write(0, hdr.ipv4.srcAddr);
                tuple_info2.write(1, hdr.ipv4.dstAddr);
                tuple_info2.write(4, (bit<32>)hdr.ipv4.protocol);
                if (hdr.tcp.isValid()) {
                    tuple_info2.write(2, (bit<32>)hdr.udp.srcPort);
                    tuple_info2.write(3, (bit<32>)hdr.udp.dstPort);
                }
                else if(hdr.udp.isValid()) {
                    tuple_info2.write(2, (bit<32>)hdr.tcp.srcPort);
                    tuple_info2.write(3, (bit<32>)hdr.tcp.dstPort);
                }
                now_i = now_i + 1;
                now_array.write(0, now_i);

                bit<32> value;
                tuple_info0.read(value, 0);
                hdr.comp[0].srcAddr = value;

                bit<32> value1;
                tuple_info0.read(value1, 1);
                hdr.comp[0].dstAddr = value1;

                bit<32> value2;
                tuple_info0.read(value2, 2);
                hdr.comp[0].srcPort = (bit<16>)value2;

                bit<32> value3;
                tuple_info0.read(value3, 3);
                hdr.comp[0].dstPort = (bit<16>)value3;

                bit<32> value4;
                tuple_info0.read(value4, 4);
                hdr.comp[0].protocol = (bit<8>)value4;

                bit<32> value10;
                tuple_info1.read(value10, 0);
                hdr.comp[1].srcAddr = value10;

                bit<32> value11;
                tuple_info1.read(value11, 1);
                hdr.comp[1].dstAddr = value11;

                bit<32> value12;
                tuple_info1.read(value12, 2);
                hdr.comp[1].srcPort = (bit<16>)value12;

                bit<32> value13;
                tuple_info1.read(value13, 3);
                hdr.comp[1].dstPort = (bit<16>)value13;

                bit<32> value14;
                tuple_info1.read(value14, 4);
                hdr.comp[1].protocol = (bit<8>)value14;

                bit<32> value20;
                tuple_info2.read(value20, 0);
                hdr.comp[2].srcAddr = value20;

                bit<32> value21;
                tuple_info2.read(value21, 1);
                hdr.comp[2].dstAddr = value21;

                bit<32> value22;
                tuple_info2.read(value22, 2);
                hdr.comp[2].srcPort = (bit<16>)value22;

                bit<32> value23;
                tuple_info2.read(value23, 3);
                hdr.comp[2].dstPort = (bit<16>)value23;

                bit<32> value24;
                tuple_info2.read(value24, 4);
                hdr.comp[2].protocol = (bit<8>)value24;




            }

            else if (now_i == 3){


                tuple_info3.write(0, hdr.ipv4.srcAddr);
                tuple_info3.write(1, hdr.ipv4.dstAddr);
                tuple_info3.write(4, (bit<32>)hdr.ipv4.protocol);
                if (hdr.tcp.isValid()) {
                    tuple_info3.write(2, (bit<32>)hdr.udp.srcPort);
                    tuple_info3.write(3, (bit<32>)hdr.udp.dstPort);
                }
                else if(hdr.udp.isValid()) {
                    tuple_info3.write(2, (bit<32>)hdr.tcp.srcPort);
                    tuple_info3.write(3, (bit<32>)hdr.tcp.dstPort);
                }
                now_i = now_i + 1;

                bit<32> value;
                tuple_info0.read(value, 0);
                hdr.comp[0].srcAddr = value;

                bit<32> value1;
                tuple_info0.read(value1, 1);
                hdr.comp[0].dstAddr = value1;

                bit<32> value2;
                tuple_info0.read(value2, 2);
                hdr.comp[0].srcPort = (bit<16>)value2;

                bit<32> value3;
                tuple_info0.read(value3, 3);
                hdr.comp[0].dstPort = (bit<16>)value3;

                bit<32> value4;
                tuple_info0.read(value4, 4);
                hdr.comp[0].protocol = (bit<8>)value4;

                bit<32> value10;
                tuple_info1.read(value10, 0);
                hdr.comp[1].srcAddr = value10;

                bit<32> value11;
                tuple_info1.read(value11, 1);
                hdr.comp[1].dstAddr = value11;

                bit<32> value12;
                tuple_info1.read(value12, 2);
                hdr.comp[1].srcPort = (bit<16>)value12;

                bit<32> value13;
                tuple_info1.read(value13, 3);
                hdr.comp[1].dstPort = (bit<16>)value13;

                bit<32> value14;
                tuple_info1.read(value14, 4);
                hdr.comp[1].protocol = (bit<8>)value14;

                bit<32> value20;
                tuple_info2.read(value20, 0);
                hdr.comp[2].srcAddr = value20;

                bit<32> value21;
                tuple_info2.read(value21, 1);
                hdr.comp[2].dstAddr = value21;

                bit<32> value22;
                tuple_info2.read(value22, 2);
                hdr.comp[2].srcPort = (bit<16>)value22;

                bit<32> value23;
                tuple_info2.read(value23, 3);
                hdr.comp[2].dstPort = (bit<16>)value23;

                bit<32> value24;
                tuple_info2.read(value24, 4);
                hdr.comp[2].protocol = (bit<8>)value24;

                bit<32> value30;
                tuple_info3.read(value30, 0);
                hdr.comp[3].srcAddr = value30;

                bit<32> value31;
                tuple_info3.read(value31, 1);
                hdr.comp[3].dstAddr = value31;

                bit<32> value32;
                tuple_info3.read(value32, 2);
                hdr.comp[3].srcPort = (bit<16>)value32;

                bit<32> value33;
                tuple_info3.read(value33, 3);
                hdr.comp[3].dstPort = (bit<16>)value33;

                bit<32> value34;
                tuple_info3.read(value34, 4);
                hdr.comp[3].protocol = (bit<8>)value34;


            }
            if (now_i >= MY_PACK) {
                // If now_i count is larger than the packet count that you want to compress,
                now_i = 0; // reset now_i to save next packets
                // process to compress and read or send the information to controller?

                now_array.write(0, now_i);
            }



            ipv4_lpm.apply();
        }

	else {
        }
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
        packet.emit(hdr.comp);
        packet.emit(hdr.ipv4);
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
