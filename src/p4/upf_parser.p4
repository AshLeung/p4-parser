#include <core.p4>
#include <ebpf_model.p4>

const bit<16> ETHERTYPE_IPV4 = 0x0800;
const bit<16> ETHERTYPE_IPV6 = 0x86dd;
const bit<16> ETHERTYPE_ARP = 0x0806;

const bit<4> IP_VERSION_V4 = 0x4;
const bit<4> IP_VERSION_V6 = 0x6;
const bit<8> IP_PROTO_ICMP = 1;
const bit<8> IP_PROTO_TCP = 6;
const bit<8> IP_PROTO_UDP = 17;
const bit<8> IP_PROTO_ICMPV6 = 58;

const bit<8> ICMP6_TYPE_NS = 135;
const bit<8> ICMP6_TYPE_NA = 136;
const bit<8> NDP_OPT_TARGET_LL_ADDR = 2;
const bit<32> NDP_FLAG_ROUTER = 0x80000000;
const bit<32> NDP_FLAG_SOLICITED = 0x40000000;

const bit<16> UDP_PORT_GTPU = 2152;
const bit<3> GTPU_VERSION = 0x1;
const bit<1> GTPU_PROTYPE = 0x1;
const bit<8> GTPU_PDU = 0xff;

header ethernet_t {
    bit<48> dst_addr;
    bit<48> src_addr;
    bit<16> ether_type;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> total_len;
    bit<16> identification;
    bit<3> flags;
    bit<13> frag_offset;
    bit<8> ttl;
    bit<8> protocol;
    bit<16> hdr_checksum;
    bit<32> src_addr;
    bit<32> dst_addr;
}

header ipv6_t {
    bit<4>   version;
    bit<8>   traffic_class;
    bit<20>  flow_label;
    bit<16>  payload_len;
    bit<8>   next_hdr;
    bit<8>   hop_limit;
    bit<128> src_addr;
    bit<128> dst_addr;
}

header tcp_t {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<3>   res;
    bit<3>   ecn;
    bit<6>   ctrl;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header udp_t {
    bit<16> src_port;
    bit<16> dst_port;
    bit<16> len;
    bit<16> checksum;
}

header arp_t {
      bit<16>  hw_type;
      bit<16>  proto_type;
      bit<8>   hw_addr_len;
      bit<8>   prot_addr_len;
      bit<16>  opcode;
      bit<48>  sha;
      bit<32>  sip;
      bit<48>  tha;
      bit<32>  tip;
}

// GTPU v1
header gtpu_t {
    bit<3>  version;    /* version */
    bit<1>  pt;         /* protocol type */
    bit<1>  spare;      /* reserved */
    bit<1>  ex_flag;    /* next extension hdr present? */
    bit<1>  seq_flag;   /* sequence no. */
    bit<1>  npdu_flag;  /* n-pdn number present ? */
    bit<8>  msgtype;    /* message type */
    bit<16> msglen;     /* message length */
    bit<32> teid;       /* tunnel endpoint id */
}

header icmp_t {
    bit<8>   type;
    bit<8>   icmp_code;
    bit<16>  checksum;
    bit<16>  identifier;
    bit<16>  sequence_number;
    bit<64>  timestamp;
}

header icmpv6_t {
    bit<8>   type;
    bit<8>   code;
    bit<16>  checksum;
}

header ndp_t {
    bit<32>      flags;
    bit<128>     target_ipv6_addr;
    // NDP option.
    bit<8>       type;
    bit<8>       length;
    bit<48>      target_mac_addr;
}

struct headers_t {
    ethernet_t    ethernet;
    ipv4_t        ipv4;
    ipv6_t        ipv6;
    tcp_t         tcp;
    udp_t         udp;
    arp_t         arp;
    // NDP 135 136
    icmpv6_t      icmpv6;
    ndp_t         ndp;
    // GTP-U
    gtpu_t        gtpu;
    ipv4_t        inner_ipv4;
    ipv6_t        inner_ipv6;
    udp_t         inner_udp;
}

parser ParserPipe (packet_in packet, out headers_t hdr) {
    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type){
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_IPV6: parse_ipv6;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_ipv6 {
        packet.extract(hdr.ipv6);
        transition select(hdr.ipv6.next_hdr) {
            IP_PROTO_TCP:    parse_tcp;
            IP_PROTO_UDP:    parse_udp;
            IP_PROTO_ICMPV6: parse_icmpv6;
            default: accept;
        }
    }

    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }


    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dst_port){
            UDP_PORT_GTPU: parse_gtpu;
            default: accept;
        }
    }

    // ICMPV6->NDP
    state parse_icmpv6 {
        packet.extract(hdr.icmpv6);
        transition select(hdr.icmpv6.type) {
            ICMP6_TYPE_NS: parse_ndp;
            ICMP6_TYPE_NA: parse_ndp;
            default: accept;
        }
    }

    state parse_ndp {
        packet.extract(hdr.ndp);
        transition accept;
    }

    // UDP 2152->GTP-U
    state parse_gtpu {
        packet.extract(hdr.gtpu);
        transition select(hdr.gtpu.version, hdr.gtpu.pt, hdr.gtpu.msgtype){
            (GTPU_VERSION, GTPU_PROTYPE, GTPU_PDU): parse_inner;
            default: accept;
        }
    }

    state parse_inner {
        transition select(packet.lookahead<bit<4>>()[3:0]){
            IP_VERSION_V4: parse_inner_ipv4;
            IP_VERSION_V6: parse_inner_ipv6;
            default: accept;
        }
    }

    state parse_inner_ipv4 {
        packet.extract(hdr.inner_ipv4);
        transition select(hdr.inner_ipv4.protocol) {
            IP_PROTO_TCP: parse_tcp;
            IP_PROTO_UDP: parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_ipv6 {
        packet.extract(hdr.inner_ipv6);
        transition select(hdr.inner_ipv6.next_hdr) {
            IP_PROTO_TCP:    parse_tcp;
            IP_PROTO_UDP:    parse_inner_udp;
            default: accept;
        }
    }

    state parse_inner_udp {
        packet.extract(hdr.inner_udp);
        transition accept;
    }
}

control ActionPipe(inout headers_t hdr, out bool pass) {
    apply {
        pass = true;
    }
}

ebpfFilter(ParserPipe(), ActionPipe()) main;