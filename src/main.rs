#![feature(slice_bytes)]
extern crate libc;
extern crate tuntap;
extern crate byteorder;

pub use libc::{uid_t, c_int};
use std::io;
use std::ffi::CString;
use tuntap::{TunTap, Tun, Tap};
use byteorder::{ByteOrder, LittleEndian};

use std::time::Duration;
use std::thread;
use std::slice::bytes;
use std::cmp;

const MTU_SIZE: usize = 1500;

extern {
    fn setreuid(ruid: uid_t, euid: uid_t) -> c_int;
    fn geteuid() -> uid_t;
    fn getuid() -> uid_t;
}

pub fn set_reuid(ruid: uid_t, euid: uid_t) -> Result<(), io::Error> {
    match unsafe { setreuid(ruid, euid) } {
        0 => Ok(()),
        -1 => Err(io::Error::last_os_error()),
        _ => unreachable!()
    }
}

pub fn print_euid() -> () {
    let uid = unsafe { geteuid() };
    println!("uid is: {}", uid);
}

fn copy_slice(src: &[u8], dst: &mut [u8]) -> usize {
    let len = cmp::min(src.len(), dst.len());
    bytes::copy_memory(& src[..len], &mut dst[..len]);
    len
}

fn to_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("0x{:02X}", b))
        .collect();
    strs.join(", ")
}

fn print_hex_and_die(msg: &str, bytes: &[u8]) {
    let byte_str = to_hex_string(bytes);
    panic!("exiting: {}, while processing packet: [{}]", msg, byte_str);
}

// packets
struct Packet {
    data: Vec<u8>,
    link: Link,
    net: Network
//    trans: T
}

impl Packet {
    fn new(data: Vec<u8>, link: Link, net: Network) -> Packet {
        Packet {
            data:  data, // the actual packet data
            link:  link, // link layer type and embedded offset
            net:   net  // network layer type and embedded offset
//            trans: trans // link layer type and embedded offset
        }
    }
}

fn make_packet(data: Vec<u8>, link: Link) {
    let network = get_network_from_data(&data[..], link);
    let transport = get_transport_from_data(&data[..], network);
//    Packet::new(data, link, network, transport)
}

fn get_network_from_data(data: &[u8], link: Link) -> Network {
    match link {
        Link::EthLink(eth) => eth.get_network(data)
    }
}

fn get_transport_from_data(data: &[u8], net: Network) -> Transport {
    match net {
        Network::Ipv4Net(net) => net.get_transport(data),
        Network::Ipv6Net(net) => net.get_transport(data),
    }
}


// link layer
enum Link {
    EthLink(Eth)
}

trait HasLinkLayer {
    fn get_network(&self, data: &[u8]) -> Network;
    fn get_payload_offset(&self, data: &[u8]) -> usize;
}

struct Eth {
    offset: usize
}

impl Eth {
    fn get_ethertype(&self, buff: &[u8]) -> u16 {
        LittleEndian::read_u16(&buff[self.offset+12..self.offset+12+2])
    }
}

impl HasLinkLayer for Eth {
    fn get_network(&self, buff: &[u8]) -> Network {
        let net_nr = self.get_ethertype(&buff[..]);
        let net_offset = self.get_payload_offset(buff);
        match net_nr {
            0x0800u16 => Network::Ipv4Net(Ipv4 { offset: net_offset }),
            // 0x86DDu16 => Ipv6 { offset: net_offset },
            // some more to implement:
            // 0x0806	Address Resolution Protocol (ARP)
            // 0x8100	VLAN-tagged frame (IEEE 802.1Q)
            //   and Shortest Path Bridging IEEE 802.1aq[8]
            // 0x8870	Jumbo Frames (proposed)[2][3]
            _         => panic!("ethertype {:x} isn't implemented", net_nr)
        }
    }

    fn get_payload_offset(&self, buff: &[u8]) -> usize {
        // we're not dealing with vlan tagging for now
        self.offset + 14
    }
}


// network layer
enum Network {
    Ipv4Net(Ipv4),
    Ipv6Net(Ipv6)
}

trait HasNetworkLayer {
    fn get_transport(&self, data: &[u8]) -> Transport;
    fn get_payload_offset(&self, data: &[u8]) -> usize;
}

// IPV4
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|          Total Length         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|      Fragment Offset    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |         Header Checksum       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                       Source Address                          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Destination Address                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
struct Ipv4 {
   offset: usize
}

impl Ipv4 {
    fn get_ihl(&self, buff: &[u8]) -> usize {
        let ihl = buff[self.offset+0];
        ihl as usize // should be shifted by 4 or therabouts
    }

    fn get_protocol(&self, buff: &[u8]) -> u8 {
        buff[self.offset+9]
    }
}

impl HasNetworkLayer for Ipv4 {
    fn get_transport(&self, buffer: &[u8]) -> Transport {
        let protocol = self.get_protocol(buffer);
        let trans_offset = self.get_payload_offset(buffer);
        match protocol {
            0x06 => Transport::TcpTrans(Tcp { offset: trans_offset }),
            _    => panic!("transport protocol {:x} isn't implemented", protocol)
        }
    }

    fn get_payload_offset(&self, buff: &[u8]) -> usize {
        let ihl = self.get_ihl(buff) as usize;
        self.offset + ihl
    }
}

// IPV6
// RFC 2460
// 
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version| Traffic Class |             Flow Label                |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |        Payload Length         |  Next Header  |   Hop Limit   |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                            Source                             |
// |                           Address                             |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               |
// |                         Destination                           |
// |                           Address                             |
// |                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
struct Ipv6 {
    offset: usize,
    extension_headers: Vec<Ipv6ExtHeader>
}

struct Ipv6ExtHeader {
    header_type: usize
}

mod Ipv6HeaderTypes {
    pub const HOP_BY_HOP: u8 = 0;
    pub const ROUTING: u8 = 43;
    pub const FRAGMENT: u8 = 44;
    pub const AUTH_HEADER: u8 = 51;
    pub const ESP: u8 = 50;
    pub const NO_NEXT: u8 = 59;
    pub const DEST_OPTS: u8 = 60;
    pub const MOBILITY: u8 = 136;
}

impl Ipv6 {
    fn get_protocol(&self, buff: &[u8]) -> u8 {
        buff[self.offset+9]
    }

    fn process_ext_headers(&self, buff: &[u8]) -> usize {
        let protocol = self.get_protocol(buff);
        let header_offset = 40;

        loop {
            match protocol {
                Ipv6HeaderTypes::HOP_BY_HOP |
                Ipv6HeaderTypes::DEST_OPTS |
                Ipv6HeaderTypes::ROUTING => {
                    // implement
                    return 4
                },
                _ => return 0
            }
        }
        header_offset
    }
}

impl HasNetworkLayer for Ipv6 {
    fn get_transport(&self, buffer: &[u8]) -> Transport {
        let protocol = self.get_protocol(buffer);
        let trans_offset = self.get_payload_offset(buffer);
        match protocol {
            0x06 => Transport::TcpTrans(Tcp { offset: trans_offset }),
            _    => panic!("transport protocol {:x} isn't implemented", protocol)
        }
    }

    fn get_payload_offset(&self, buff: &[u8]) -> usize {
        let pkt_end = 40;
        let ext_header_len = self.process_ext_headers(buff);
        self.offset + pkt_end + ext_header_len
    }
}

// ICMP
// RFC 792
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                             unused                            |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Internet Header + 64 bits of Original Data Datagram      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//
// type / code
//  0 = Echo reply
//  3 = Destination unreachable
//      Code
//       0	Net unreachable
//       1	Host unreachable
//       2	Protocol unreachable
//       3	Port unreachable
//       4	Fragmentation needed but DF set
//       5	Source route failed
//       6	Destination network unknown
//       7	Destination host unknown
//       8	Source host isolated
//       9	Network administratively prohibited
//      10	Host administratively prohibited
//      11	Network unreachable for requested TOS
//      12	Host unreachable for requested TOS
//      13	Communication administratively prohibited
//  4 = Source quench
//  5 = Redirect
//      Code
//       0	Redirect datagram for the network
//       1	Redirect datagram for the host
//       2	Redirect datagram for the TOS and network
//       3	Redirect datagram for the TOS and host
//  8 = Echo request
//  9 = Router advertisement
// 10 = Router selection
// 11 = Time exceeded
//      Code
//       0	Time to live exceeded in transit
//       1	Fragment reassembly time exceeded
// 12 = Parameter problem
//      Code
//       0	Pointer indicates the error
//       1	Missing a required option
//       2	Bad length
// 13 = Timestamp
// 14 = Timestamp reply
// 15 = Information request
// 16 = Information reply
// 17 = Address mask request
// 18 = Address mask reply
// 30 = Traceroute (probably just Microsoft hosts, traceroute
//      should be done via UDP)

// ICMPv6
// RFC 4443
//
//  0                   1                   2                   3
//  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |     Type      |     Code      |          Checksum             |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |      Internet Header + 64 bits of Original Data Datagram      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

// ICMPv6 error messages
//   1  Destination Unreachable
//   2  Packet Too Big
//   3  Time Exceeded
//   4  Parameter Problem
// 100  Private experimentation
// 101  Private experimentation
// 127  Reserved for expansion

// ICMPv6 informational messages
// 128  Echo Request
// 129  Echo Reply
// 130  Multicast Listener Query
// 131  Multicast Listener Report
// 132  Multicast Listener Done
// 133  Router Solicitation     (NDP)
// 134  Router Advertisement    (NDP)
// 135  Neighbor Solicitation   (NDP)
// 136  Neighbor Advertisement  (NDP)
// 137  Redirect Message        (NDP)
// 138  Router Renumbering
// 139  ICMP Node Information Query
// 140  ICMP Node Information Response
// 141  Inverse Neighbor Discovery Solicitation Message    (NDP)
// 142  Inverse Neighbor Discovery Advertistement Message  (NDP)
// 143  Version 2 Multicast Listener Report
// 144  Home Agent Address Discovery Request Message
// 145  Home Agent Address Discovery Reply Message
// 146  Mobile Prefix Solicitation
// 147  Mobile Prefix Advertisement
// 148  Certifcation Path Solicitation   (SEND)
// 149  Certifcation Path Advertisement  (SEND)
// 150  used by experimental mobility protocols such as Seamoby
// 151  Multicast Router Advertisement  (MRD)
// 152  Multicast Router Solicitaion    (MRD)
// 153  Multicast Router Termination    (MRD)
// 154  FMIPv6 Messages
// 155  RPL Control Message
// 200  Private experimentation
// 201  Private experimentation
// 255  Reserved for expansion

// transport layer

enum Transport {
    TcpTrans(Tcp)
}

// TCP
// RFC 793, updated by RFC 1122, and RFC 3168
// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |           |U|A|P|R|S|F|                               |
// | Offset| Reserved  |R|C|S|S|Y|I|            Window             |
// |       |           |G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Options                    |    Padding    |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |   .... data ....                                              |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

struct Tcp {
    offset: usize
}

struct Udp {
    offset: usize
}

// mainzy
fn main() {
    print_euid();
    let _ = set_reuid(0, unsafe { getuid() });
    print_euid();

    let old_euid = unsafe { geteuid() };
    let _ = set_reuid(0,0);

    // let _ = set_reuid(0,old_euid);

    let mut tap = TunTap::create_named(Tap, &CString::new("tap0").unwrap());
    tap.add_address(CString::new("900::2").unwrap());

    println!("bin: {}", 0x87);
    
    loop {
        let mut buffer = [0u8; MTU_SIZE];
        let result = tap.read(&mut buffer).unwrap();
        
        let mut out = [0u8; MTU_SIZE];
        let len = copy_slice(&result, &mut out);

        for x in 22..38 {
            out[x] = result[x+16];
        }
        for x in 38..54 {
            out[x] = result[x-16];
        }

        tap.write(&out[..len]);
        // println!("result: {}", to_hex_string(result));
    }
}

// def ping_server() -> () {
    
// }

#[test]
fn test_icmpv6_mldv2_packet() -> () {

    
    let icmp6_packet = vec!(
        // eth
        0x33, 0x33, 0x00, 0x00, 0x00, 0x16, // mac dest
        0x06, 0xD8, 0xB8, 0xB8, 0x1B, 0x41, // mac src
        0x86, 0xDD, // ipv6

        // ipv6
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x24, 0x00, 0x01,
        
        0xFE, 0x80, 0x00, 0x00, // dst
        0x00, 0x00, 0x00, 0x00,
        0x04, 0xD8, 0xB8, 0xFF,
        0xFE, 0xB8, 0x1B, 0x41,
        
        0xFF, 0x02, 0x00, 0x00, // src
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x16,

        0x3A, 0x00, 0x05, 0x02, // hop-by-hop option
        0x00, 0x00, 0x01, 0x00,
        
        // icmpv6
        0x8F, 0x00, 0x97, 0x3E, // 0x8F = 143 = Multicast Listener Discovery (MLDv2)
        0x00, 0x00, 0x00, 0x01, //   reports (RFC 3810)
        0x04, 0x00, 0x00, 0x00, 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFB);

    let icmp6_echo_packet = vec!(
        // eth
        0x33, 0x33, 0xFF, 0x00, 0x00, 0x03,
        0x72, 0x63, 0x32, 0x7B, 0x04, 0x21,
        0x86, 0xDD,

        // ipv6
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x3A, 0xFF,

        0x09, 0x00, 0x00, 0x00, // dst
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02,


        0xFF, 0x02, 0x00, 0x00, // src
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0xFF, 0x00, 0x00, 0x03,

        0x87, 0x00, 0xBE, 0x97,
        0x00, 0x00, 0x00, 0x00,

        0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x01, 0x72, 0x63, 0x32, 0x7B, 0x04, 0x21);
}
