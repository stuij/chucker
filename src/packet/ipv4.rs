use super::pkt;
use super::tcp;

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
pub struct Ipv4 {
   pub offset: usize
}


netbits!{
    Ipv4,
    version: 4,
    ihl: 4,
    tos: 8,
    len: 16,
    ident: 16,
    flag_res: 1,
    flag_DF: 1,
    flag_MF: 1,
    frag_offs: 13,
    ttl: 8,
    protocol: 8,
    header_chk: 16,
    src_addr: [8; 4],
    dst_addr: [8; 4]
}

impl pkt::HasNetworkLayer for Ipv4 {
    fn get_transport(&self, buffer: &[u8]) -> pkt::Transport {
        let protocol = self.get_protocol(buffer);
        let trans_offset = self.get_payload_offset(buffer);
        match protocol {
            0x06 => pkt::Transport::TcpTrans(tcp::Tcp { offset: trans_offset }),
            _    => panic!("transport protocol {:x} isn't implemented", protocol)
        }
    }

    fn get_payload_offset(&self, buff: &[u8]) -> usize {
        let ihl = self.get_ihl(buff) as usize;
        self.offset + ihl
    }
}
