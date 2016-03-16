use std::net;

use super::pkt;
use super::pkt::{write_imm, write_arr};
use super::tcp;

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
pub struct Ipv6 {
    pub offset: usize,
    // extension_headers: Vec<Ipv6ExtHeader>
}

netbits!{
    Ipv6, write_imm, write_arr,
    version: 4,
    traffic_class: 8,
    flow_label: 20,
    payload_len: 16,
    nxt_header: 8,
    hop_limit: 8,
    src: [8; 16; print_ipv6],
    dst: [8; 16; print_ipv6]
}

fn print_ipv6(name: &str, buff: &[u8]) {
    let buff16 = (0..15)
        .filter(|&x| x % 2 == 0)
        .map(|x| (buff[x] as u16) << 8 | buff[x + 1] as u16)
        .collect::<Vec<u16>>();

    let addr = net::Ipv6Addr::new(buff16[0], buff16[1], buff16[2], buff16[3],
                                  buff16[4], buff16[5], buff16[6], buff16[7]);
    let addr_str = format!("{}", addr);
    println!("  {: <15}: {: >40}", name, addr_str);
}

struct Ipv6ExtHeader {
    header_type: usize
}

mod header_types {
    pub const HOP_BY_HOP:  u8 = 0;
    pub const ROUTING:     u8 = 43;
    pub const FRAGMENT:    u8 = 44;
    pub const AUTH_HEADER: u8 = 51;
    pub const ESP:         u8 = 50;
    pub const NO_NEXT:     u8 = 59;
    pub const DEST_OPTS:   u8 = 60;
    pub const MOBILITY:    u8 = 136;
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
                header_types::HOP_BY_HOP |
                header_types::DEST_OPTS |
                header_types::ROUTING => {
                    // implement
                    return 4
                },
                _ => return 0
            }
        }
        header_offset
    }
}

impl pkt::HasNetworkLayer for Ipv6 {
    fn get_transport(&self, buffer: &[u8]) -> pkt::Transport {
        let protocol = self.get_protocol(buffer);
        let trans_offset = self.get_payload_offset(buffer);
        match protocol {
            0x06 => pkt::Transport::TcpTrans(tcp::Tcp { offset: trans_offset }),
            _    => panic!("transport protocol {:x} isn't implemented", protocol)
        }
    }

    fn get_payload_offset(&self, buff: &[u8]) -> usize {
        let pkt_end = 40;
        let ext_header_len = self.process_ext_headers(buff);
        self.offset + pkt_end + ext_header_len
    }

    fn print(&self, buff: &[u8]) {
        println!("ipv6:");
        self.print_fields(buff);
    }
}
