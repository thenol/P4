/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

// NOTE: new type added here
const bit<16> TYPE_MYTUNNEL = 0x1212;
const bit<16> TYPE_IPV4 = 0x800;


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

// NOTE: added new header type
header myTunnel_t {
    bit<16> proto_id;
    bit<16> dst_id;
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
header IPv4_options_h {
   bit<32> options;
}
struct metadata {
    /* empty */
}

// NOTE: Added new header type to headers struct
struct headers {
    ethernet_t   ethernet;
    myTunnel_t   myTunnel;
    ipv4_t       ipv4;
    IPv4_options_h    ipv4options;
}

enum PSA_HashAlgorithm_t {
  IDENTITY,
  CRC32,
  CRC32_CUSTOM,
  CRC16,
  CRC16_CUSTOM,
  ONES_COMPLEMENT16,  /// One's complement 16-bit sum used for IPv4 headers,
                      /// TCP, and UDP.
  TARGET_DEFAULT      /// target implementation defined
}


error { HeaderNotValid,HeaderNormal }

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

// TODO: Update the parser to parse the myTunnel header as well
parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        // Hash<bit<32>>(PSA_HashAlgorithm_t.CRC32) h;
        // bit<16> hash_value = h.get_hash(hdr.ether);
        // verify(hash_value==hdr.ethernet.)
        transition select(hdr.ethernet.etherType) {
            TYPE_IPV4 : parse_ipv4;
            default : accept;
        }
    }

    /*state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }*/
    state parse_ipv4 {
       packet.extract(hdr.ipv4);
    //    verify(hdr.ipv4.ihl >= 5, error.InvalidIPv4Header);
       transition select (hdr.ipv4.ihl) {
           5: parse_ipv4_top_level;
           _: parse_ipv4_options;
        }
    }
    state parse_ipv4_options {
        packet.extract(hdr.ipv4options);
        transition parse_ipv4_top_level;
   }
   
   //state for ipv4 default parse
   state parse_ipv4_top_level {
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
        mark_to_drop();
    }
    
    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }
    action add_options(){
        //0,2,number=5,length=4,data=0xffff  => 0 10 00011 00000010 00000010 11111111 => 0x4302ffff
        hdr.ipv4options.options = (bit<32>) 0x43020202;
        hdr.ipv4.ihl =hdr.ipv4.ihl+1;
    }
    
    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            //add_options;
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    // TODO: declare a new action: myTunnel_forward(egressSpec_t port)


    // TODO: declare a new table: myTunnel_exact
    // TODO: also remember to add table entries!


    apply {
        // TODO: Update control flow
        if (hdr.ipv4.isValid()) {
            /*
            In addition, headers support the following methods:
                The method isValid() returns the value of the “validity” bit of the header.
                The method setValid() sets the header's validity bit to “true”. It can only be applied to an l-value.
                The method setInvalid() sets the header's validity bit to “false”. It can only be applied to an l-value.
            */
            if(!hdr.ipv4options.isValid()&&hdr.ipv4.ihl<=5){//to control the operation of adding-option happens only one time
                hdr.ipv4options.setValid();
                add_options();//modify option field;
            }

            ipv4_lpm.apply();
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
         //if(hdr.ipv4.ihl>5){
             update_checksum(
                hdr.ipv4.isValid()&&hdr.ipv4.ihl>5,
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
                    hdr.ipv4.dstAddr,
                    hdr.ipv4options.options},
                    hdr.ipv4.hdrChecksum,
                    HashAlgorithm.csum16);
         //}else{
             update_checksum(
                hdr.ipv4.isValid()&&hdr.ipv4.ihl<=5,
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
                    hdr.ipv4.dstAddr},
                    hdr.ipv4.hdrChecksum,
                    HashAlgorithm.csum16);
         //}
	
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        // TODO: emit myTunnel header as well
        packet.emit(hdr.ipv4);
        packet.emit(hdr.ipv4options);
        
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
