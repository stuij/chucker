use super::packet;
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

impl Ipv4 {
    fn get_ihl(&self, buff: &[u8]) -> usize {
        let ihl = buff[self.offset+0];
        ihl as usize // should be shifted by 4 or therabouts
    }

    fn get_protocol(&self, buff: &[u8]) -> u8 {
        buff[self.offset+9]
    }
}

impl packet::HasNetworkLayer for Ipv4 {
    fn get_transport(&self, buffer: &[u8]) -> packet::Transport {
        let protocol = self.get_protocol(buffer);
        let trans_offset = self.get_payload_offset(buffer);
        match protocol {
            0x06 => packet::Transport::TcpTrans(tcp::Tcp { offset: trans_offset }),
            _    => panic!("transport protocol {:x} isn't implemented", protocol)
        }
    }

    fn get_payload_offset(&self, buff: &[u8]) -> usize {
        let ihl = self.get_ihl(buff) as usize;
        self.offset + ihl
    }
}
