use super::packet;
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

impl packet::HasNetworkLayer for Ipv6 {
    fn get_transport(&self, buffer: &[u8]) -> packet::Transport {
        let protocol = self.get_protocol(buffer);
        let trans_offset = self.get_payload_offset(buffer);
        match protocol {
            0x06 => packet::Transport::TcpTrans(tcp::Tcp { offset: trans_offset }),
            _    => panic!("transport protocol {:x} isn't implemented", protocol)
        }
    }

    fn get_payload_offset(&self, buff: &[u8]) -> usize {
        let pkt_end = 40;
        let ext_header_len = self.process_ext_headers(buff);
        self.offset + pkt_end + ext_header_len
    }
}