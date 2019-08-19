#include <core.p4>
#include <v1model.p4>

struct srv6_meta_t {
    bit<32> teid;
    bit<96> EndMGTP6E_SRGW;
    bit<8>  segmentsLeft;
    bit<16> ipv6_payloadLen;
}

header ethernet_t {
    bit<48> dstAddr;
    bit<48> srcAddr;
    bit<16> etherType;
}

header gtpu_t {
    bit<8>  flags;
    bit<8>  type;
    bit<16> length;
    bit<32> teid;
}

header ipv4_t {
    bit<4>  version;
    bit<4>  ihl;
    bit<8>  diffserv;
    bit<16> totalLen;
    bit<16> identification;
    bit<3>  flags;
    bit<13> fragOffset;
    bit<8>  ttl;
    bit<8>  protocol;
    bit<16> hdrChecksum;
    bit<32> srcAddr;
    bit<32> dstAddr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   trafficClass;
    bit<20>  flowLabel;
    bit<16>  payloadLen;
    bit<8>   nextHdr;
    bit<8>   hopLimit;
    bit<128> srcAddr;
    bit<128> dstAddr;
}

header ipv6_srh_t {
    bit<8>  nextHeader;
    bit<8>  hdrExtLen;
    bit<8>  routingType;
    bit<8>  segmentsLeft;
    bit<8>  lastEntry;
    bit<8>  flags;
    bit<16> tag;
}

header tcp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<8>  flags;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header ipv6_srh_segment_t {
    bit<128> sid;
}

struct metadata {
    @name(".srv6_meta") 
    srv6_meta_t srv6_meta;
}

struct headers {
    @name(".ethernet") 
    ethernet_t            ethernet;
    @name(".gtpu") 
    gtpu_t                gtpu;
    @name(".gtpu_ipv4") 
    ipv4_t                gtpu_ipv4;
    @name(".gtpu_ipv6") 
    ipv6_t                gtpu_ipv6;
    @name(".ipv4") 
    ipv4_t                ipv4;
    @name(".ipv6") 
    ipv6_t                ipv6;
    @name(".ipv6_inner") 
    ipv6_t                ipv6_inner;
    @name(".ipv6_srh") 
    ipv6_srh_t            ipv6_srh;
    @name(".tcp") 
    tcp_t                 tcp;
    @name(".udp") 
    udp_t                 udp;
    @name(".ipv6_srh_segment_list") 
    ipv6_srh_segment_t[4] ipv6_srh_segment_list;
}

parser ParserImpl(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".parse_ethernet") state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            16w0x800: parse_ipv4;
            16w0x86dd: parse_ipv6;
            default: accept;
        }
    }
    @name(".parse_gtpu") state parse_gtpu {
        packet.extract(hdr.gtpu);
        transition select((packet.lookahead<bit<4>>())[3:0]) {
            4w0x4: parse_gtpu_ipv4;
            4w0x6: parse_gtpu_ipv6;
        }
    }
    @name(".parse_gtpu_ipv4") state parse_gtpu_ipv4 {
        packet.extract(hdr.gtpu_ipv4);
        transition accept;
    }
    @name(".parse_gtpu_ipv6") state parse_gtpu_ipv6 {
        packet.extract(hdr.gtpu_ipv6);
        transition accept;
    }
    @name(".parse_ipv4") state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            8w6: parse_tcp;
            8w17: parse_udp;
            default: accept;
        }
    }
    @name(".parse_ipv6") state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.nextHdr) {
            8w6: parse_tcp;
            8w17: parse_udp;
            8w43: parse_ipv6_srh;
            default: accept;
        }
    }
    @name(".parse_ipv6_inner") state parse_ipv6_inner {
        packet.extract(hdr.ipv6_inner);
        transition accept;
    }
    @name(".parse_ipv6_srh") state parse_ipv6_srh {
        packet.extract(hdr.ipv6_srh);
        transition parse_ipv6_srh_seg0;
    }
    @name(".parse_ipv6_srh_payload") state parse_ipv6_srh_payload {
        transition select(hdr.ipv6_srh.nextHeader) {
            8w4: parse_ipv4;
            8w6: parse_tcp;
            8w17: parse_udp;
            8w41: parse_ipv6_inner;
            default: accept;
        }
    }
    @name(".parse_ipv6_srh_seg0") state parse_ipv6_srh_seg0 {
        packet.extract(hdr.ipv6_srh_segment_list[0]);
        transition select(hdr.ipv6_srh.lastEntry) {
            8w0: parse_ipv6_srh_payload;
            default: parse_ipv6_srh_seg1;
        }
    }
    @name(".parse_ipv6_srh_seg1") state parse_ipv6_srh_seg1 {
        packet.extract(hdr.ipv6_srh_segment_list[1]);
        transition select(hdr.ipv6_srh.lastEntry) {
            8w1: parse_ipv6_srh_payload;
            default: parse_ipv6_srh_seg2;
        }
    }
    @name(".parse_ipv6_srh_seg2") state parse_ipv6_srh_seg2 {
        packet.extract(hdr.ipv6_srh_segment_list[2]);
        transition select(hdr.ipv6_srh.lastEntry) {
            8w2: parse_ipv6_srh_payload;
            default: parse_ipv6_srh_seg3;
        }
    }
    @name(".parse_ipv6_srh_seg3") state parse_ipv6_srh_seg3 {
        packet.extract(hdr.ipv6_srh_segment_list[3]);
        transition parse_ipv6_srh_payload;
    }
    @name(".parse_tcp") state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }
    @name(".parse_udp") state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            16w2152: parse_gtpu;
            default: accept;
        }
    }
    @name(".start") state start {
        transition parse_ethernet;
    }
}

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    @name(".forward") action forward(bit<9> port) {
        standard_metadata.egress_spec = port;
    }
    @name("._drop") action _drop() {
        mark_to_drop();
    }
    @name(".gtpu_encap_v6") action gtpu_encap_v6(bit<128> srcAddr, bit<128> dstAddr, bit<16> srcPort, bit<16> dstPort, bit<8> type, bit<32> teid) {
        hdr.udp.setValid();
        hdr.gtpu.setValid();
        hdr.gtpu_ipv6.setValid();
        hdr.gtpu_ipv6 = hdr.ipv6;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w36;
        hdr.ipv6.nextHdr = 8w17;
        hdr.ipv6.srcAddr = srcAddr;
        hdr.ipv6.dstAddr = dstAddr;
        hdr.udp.srcPort = srcPort;
        hdr.udp.dstPort = dstPort;
        hdr.udp.length_ = hdr.ipv6.payloadLen - 16w20;
        hdr.gtpu.flags = 8w0x30;
        hdr.gtpu.type = type;
        hdr.gtpu.length = hdr.udp.length_ - 16w16;
        hdr.gtpu.teid = teid;
    }
    @name(".gtpu_decap_v6") action gtpu_decap_v6() {
        hdr.ipv6 = hdr.gtpu_ipv6;
        hdr.udp.setInvalid();
        hdr.gtpu.setInvalid();
        hdr.gtpu_ipv6.setInvalid();
    }
    @name(".ipv6_srh_insert") action ipv6_srh_insert(bit<8> proto) {
        hdr.ipv6_srh.setValid();
        hdr.ipv6_srh.nextHeader = proto;
        hdr.ipv6_srh.hdrExtLen = 8w0;
        hdr.ipv6_srh.routingType = 8w4;
        hdr.ipv6_srh.segmentsLeft = 8w0;
        hdr.ipv6_srh.lastEntry = 8w0;
        hdr.ipv6_srh.flags = 8w0;
        hdr.ipv6_srh.tag = 16w0;
    }
    @name(".srv6_T_Insert1") action srv6_T_Insert1(bit<128> sid0) {
        ipv6_srh_insert(hdr.ipv6.nextHdr);
        hdr.ipv6_srh_segment_list[0].setValid();
        hdr.ipv6_srh_segment_list[0].sid = hdr.ipv6.dstAddr;
        hdr.ipv6_srh_segment_list[1].setValid();
        hdr.ipv6_srh_segment_list[1].sid = sid0;
        hdr.ipv6_srh.hdrExtLen = 8w4;
        hdr.ipv6_srh.segmentsLeft = 8w1;
        hdr.ipv6_srh.lastEntry = 8w1;
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6.dstAddr = sid0;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w40;
    }
    @name(".srv6_T_Insert2") action srv6_T_Insert2(bit<128> sid0, bit<128> sid1) {
        ipv6_srh_insert(hdr.ipv6.nextHdr);
        hdr.ipv6_srh_segment_list[0].setValid();
        hdr.ipv6_srh_segment_list[0].sid = hdr.ipv6.dstAddr;
        hdr.ipv6_srh_segment_list[1].setValid();
        hdr.ipv6_srh_segment_list[1].sid = sid1;
        hdr.ipv6_srh_segment_list[2].setValid();
        hdr.ipv6_srh_segment_list[2].sid = sid0;
        hdr.ipv6_srh.hdrExtLen = 8w6;
        hdr.ipv6_srh.segmentsLeft = 8w2;
        hdr.ipv6_srh.lastEntry = 8w2;
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6.dstAddr = sid0;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w56;
    }
    @name(".srv6_T_Insert3") action srv6_T_Insert3(bit<128> sid0, bit<128> sid1, bit<128> sid2) {
        ipv6_srh_insert(hdr.ipv6.nextHdr);
        hdr.ipv6_srh_segment_list[0].setValid();
        hdr.ipv6_srh_segment_list[0].sid = hdr.ipv6.dstAddr;
        hdr.ipv6_srh_segment_list[1].setValid();
        hdr.ipv6_srh_segment_list[1].sid = sid2;
        hdr.ipv6_srh_segment_list[2].setValid();
        hdr.ipv6_srh_segment_list[2].sid = sid1;
        hdr.ipv6_srh_segment_list[3].setValid();
        hdr.ipv6_srh_segment_list[3].sid = sid0;
        hdr.ipv6_srh.hdrExtLen = 8w8;
        hdr.ipv6_srh.segmentsLeft = 8w3;
        hdr.ipv6_srh.lastEntry = 8w3;
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6.dstAddr = sid0;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w72;
    }
    @name(".ipv6_encap_ipv6") action ipv6_encap_ipv6(bit<128> srcAddr, bit<128> dstAddr) {
        hdr.ipv6_inner.setValid();
        hdr.ipv6_inner = hdr.ipv6;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w40;
        hdr.ipv6.nextHdr = 8w41;
        hdr.ipv6.srcAddr = srcAddr;
        hdr.ipv6.dstAddr = dstAddr;
    }
    @name(".srv6_T_Encaps2") action srv6_T_Encaps2(bit<128> srcAddr, bit<128> sid0, bit<128> sid1) {
        ipv6_encap_ipv6(srcAddr, sid0);
        ipv6_srh_insert(8w41);
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6_srh_segment_list[0].setValid();
        hdr.ipv6_srh_segment_list[0].sid = sid1;
        hdr.ipv6_srh_segment_list[1].setValid();
        hdr.ipv6_srh_segment_list[1].sid = sid0;
        hdr.ipv6_srh.hdrExtLen = 8w4;
        hdr.ipv6_srh.segmentsLeft = 8w1;
        hdr.ipv6_srh.lastEntry = 8w1;
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6.dstAddr = sid0;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w40;
    }
    @name(".srv6_T_Encaps1") action srv6_T_Encaps1(bit<128> srcAddr, bit<128> sid0) {
        ipv6_encap_ipv6(srcAddr, sid0);
        ipv6_srh_insert(8w41);
        hdr.ipv6_srh_segment_list[0].setValid();
        hdr.ipv6_srh_segment_list[0].sid = sid0;
        hdr.ipv6_srh.hdrExtLen = 8w2;
        hdr.ipv6_srh.segmentsLeft = 8w0;
        hdr.ipv6_srh.lastEntry = 8w0;
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6.dstAddr = sid0;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w24;
    }
    @name(".srv6_T_Encaps3") action srv6_T_Encaps3(bit<128> srcAddr, bit<128> sid0, bit<128> sid1, bit<128> sid2) {
        ipv6_encap_ipv6(srcAddr, sid0);
        ipv6_srh_insert(8w41);
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6_srh_segment_list[0].setValid();
        hdr.ipv6_srh_segment_list[0].sid = sid2;
        hdr.ipv6_srh_segment_list[1].setValid();
        hdr.ipv6_srh_segment_list[1].sid = sid1;
        hdr.ipv6_srh_segment_list[2].setValid();
        hdr.ipv6_srh_segment_list[2].sid = sid0;
        hdr.ipv6_srh.hdrExtLen = 8w6;
        hdr.ipv6_srh.segmentsLeft = 8w2;
        hdr.ipv6_srh.lastEntry = 8w2;
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6.dstAddr = sid0;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w56;
    }
    @name(".srv6_T_Encaps_Red2") action srv6_T_Encaps_Red2(bit<128> srcAddr, bit<128> sid0, bit<128> sid1) {
        ipv6_encap_ipv6(srcAddr, sid0);
        ipv6_srh_insert(8w41);
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6_srh_segment_list[0].setValid();
        hdr.ipv6_srh_segment_list[0].sid = sid1;
        hdr.ipv6_srh.hdrExtLen = 8w2;
        hdr.ipv6_srh.segmentsLeft = 8w1;
        hdr.ipv6_srh.lastEntry = 8w0;
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6.dstAddr = sid0;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w24;
    }
    @name(".srv6_T_Encaps_Red3") action srv6_T_Encaps_Red3(bit<128> srcAddr, bit<128> sid0, bit<128> sid1, bit<128> sid2) {
        ipv6_encap_ipv6(srcAddr, sid0);
        ipv6_srh_insert(8w41);
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6_srh_segment_list[0].setValid();
        hdr.ipv6_srh_segment_list[0].sid = sid2;
        hdr.ipv6_srh_segment_list[1].setValid();
        hdr.ipv6_srh_segment_list[1].sid = sid1;
        hdr.ipv6_srh.hdrExtLen = 8w4;
        hdr.ipv6_srh.segmentsLeft = 8w2;
        hdr.ipv6_srh.lastEntry = 8w1;
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6.dstAddr = sid0;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w40;
    }
    @name(".srv6_End0") action srv6_End0() {
        hdr.ipv6_srh.segmentsLeft = hdr.ipv6_srh.segmentsLeft - 8w1;
        hdr.ipv6.dstAddr = hdr.ipv6_srh_segment_list[0].sid;
    }
    @name(".srv6_End1") action srv6_End1() {
        hdr.ipv6_srh.segmentsLeft = hdr.ipv6_srh.segmentsLeft - 8w1;
        hdr.ipv6.dstAddr = hdr.ipv6_srh_segment_list[1].sid;
    }
    @name(".srv6_End_DT6") action srv6_End_DT6() {
        hdr.ipv6 = hdr.ipv6_inner;
        hdr.ipv6_srh.setInvalid();
        hdr.ipv6_srh_segment_list[0].setInvalid();
        hdr.ipv6_srh_segment_list[1].setInvalid();
        hdr.ipv6_srh_segment_list[2].setInvalid();
        hdr.ipv6_srh_segment_list[3].setInvalid();
        hdr.ipv6_inner.setInvalid();
    }
    @name(".srv6_End_M_GTP6_D2") action srv6_End_M_GTP6_D2(bit<128> srcAddr, bit<128> sid0, bit<128> sid1) {
        hdr.udp.setInvalid();
        hdr.gtpu.setInvalid();
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen - 16w16;
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w24;
        ipv6_srh_insert(8w0);
        hdr.ipv6_srh.nextHeader = 8w41;
        hdr.ipv6_srh_segment_list[0].setValid();
        hdr.ipv6_srh_segment_list[0].sid = sid1;
        hdr.ipv6_srh.hdrExtLen = 8w2;
        hdr.ipv6_srh.segmentsLeft = 8w1;
        hdr.ipv6_srh.lastEntry = 8w0;
        hdr.ipv6.srcAddr = srcAddr;
        hdr.ipv6.dstAddr = sid0;
    }
    @name(".srv6_End_M_GTP6_D3") action srv6_End_M_GTP6_D3(bit<128> srcAddr, bit<128> sid0, bit<128> sid1, bit<128> sid2) {
        hdr.udp.setInvalid();
        hdr.gtpu.setInvalid();
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen - 16w16;
        hdr.ipv6.nextHdr = 8w43;
        hdr.ipv6.payloadLen = hdr.ipv6.payloadLen + 16w40;
        ipv6_srh_insert(8w0);
        hdr.ipv6_srh.nextHeader = 8w41;
        hdr.ipv6_srh_segment_list[0].setValid();
        hdr.ipv6_srh_segment_list[0].sid = sid2;
        hdr.ipv6_srh_segment_list[1].setValid();
        hdr.ipv6_srh_segment_list[1].sid = sid1;
        hdr.ipv6_srh.hdrExtLen = 8w4;
        hdr.ipv6_srh.segmentsLeft = 8w2;
        hdr.ipv6_srh.lastEntry = 8w1;
        hdr.ipv6.srcAddr = srcAddr;
        hdr.ipv6.dstAddr = sid0;
    }
    @name(".srv6_End_M_GTP6_E") action srv6_End_M_GTP6_E(bit<128> srcAddr) {
        hdr.ipv6_srh.segmentsLeft = hdr.ipv6_srh.segmentsLeft - 8w1;
        hdr.ipv6.srcAddr = srcAddr;
        meta.srv6_meta.teid = 32w0xffffffff & (bit<32>)hdr.ipv6.dstAddr;
        hdr.ipv6_srh.setInvalid();
        hdr.ipv6_srh_segment_list[0].setInvalid();
        hdr.ipv6_srh_segment_list[1].setInvalid();
        hdr.ipv6_srh_segment_list[2].setInvalid();
        hdr.ipv6_srh_segment_list[3].setInvalid();
        hdr.ipv6.dstAddr = hdr.ipv6_srh_segment_list[0].sid;
        meta.srv6_meta.ipv6_payloadLen = hdr.ipv6.payloadLen + 16w8 + 16w8 - 16w8 - 16w16;
        hdr.ipv6.payloadLen = meta.srv6_meta.ipv6_payloadLen;
        hdr.ipv6.nextHdr = 8w17;
        hdr.udp.setValid();
        hdr.gtpu.setValid();
        hdr.gtpu_ipv6.setValid();
        hdr.gtpu_ipv6 = hdr.ipv6_inner;
        hdr.ipv6_inner.setInvalid();
        hdr.udp.srcPort = 16w1000;
        hdr.udp.dstPort = 16w2152;
        hdr.udp.length_ = hdr.ipv6.payloadLen;
        hdr.gtpu.teid = meta.srv6_meta.teid;
        hdr.gtpu.flags = 8w0x30;
        hdr.gtpu.type = 8w255;
        hdr.gtpu.length = hdr.udp.length_ - 16w16;
    }
    @name(".fwd") table fwd {
        actions = {
            forward;
            _drop;
        }
        key = {
            standard_metadata.ingress_port: exact;
        }
    }
    @name(".gtpu_v6") table gtpu_v6 {
        actions = {
            gtpu_encap_v6;
            gtpu_decap_v6;
        }
        key = {
            hdr.ipv6.dstAddr: exact;
        }
    }
    @name(".srv6_localsid") table srv6_localsid {
        actions = {
            srv6_T_Insert1;
            srv6_T_Insert2;
            srv6_T_Insert3;
            srv6_T_Encaps2;
            srv6_T_Encaps1;
            srv6_T_Encaps3;
            srv6_T_Encaps_Red2;
            srv6_T_Encaps_Red3;
            srv6_End0;
            srv6_End1;
            srv6_End_DT6;
            srv6_End_M_GTP6_D2;
            srv6_End_M_GTP6_D3;
            srv6_End_M_GTP6_E;
        }
        key = {
            hdr.ipv6.dstAddr: exact;
        }
    }
    apply {
        fwd.apply();
        gtpu_v6.apply();
        srv6_localsid.apply();
    }
}

control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    apply {
    }
}

control DeparserImpl(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv6);
        packet.emit(hdr.ipv6_srh);
        packet.emit(hdr.ipv6_srh_segment_list[0]);
        packet.emit(hdr.ipv6_srh_segment_list[1]);
        packet.emit(hdr.ipv6_srh_segment_list[2]);
        packet.emit(hdr.ipv6_srh_segment_list[3]);
        packet.emit(hdr.ipv6_inner);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.gtpu);
        packet.emit(hdr.gtpu_ipv6);
        packet.emit(hdr.gtpu_ipv4);
        packet.emit(hdr.tcp);
    }
}

control verifyChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

control computeChecksum(inout headers hdr, inout metadata meta) {
    apply {
    }
}

V1Switch(ParserImpl(), verifyChecksum(), ingress(), egress(), computeChecksum(), DeparserImpl()) main;

