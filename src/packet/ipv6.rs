use super::pkt;
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
    Ipv6,
    version: 4,
    traffic_class: 8,
    flow_label: 20,
    payload_len: 16,
    nxt_header: 8,
    hop_limit: 8,
    src: [8; 16],
    dst: [8; 16]
}

struct Ipv6ExtHeader {
    header_type: usize
}

mod header_types {
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
}
