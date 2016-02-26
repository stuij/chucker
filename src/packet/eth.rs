use super::packet;
use super::ipv4;
use byteorder::{ByteOrder, LittleEndian};

pub struct Eth {
    pub offset: usize
}

netbits!{
    Eth,
    version: 16,
    source_address: [16; 2]
}

impl Eth {
    fn get_ethertype(&self, buff: &[u8]) -> u16 {
        LittleEndian::read_u16(&buff[self.offset+12..self.offset+12+2])
    }
}

impl packet::HasLinkLayer for Eth {
    fn get_network(&self, buff: &[u8]) -> packet::Network {
        let net_nr = self.get_ethertype(&buff[..]);
        let net_offset = self.get_payload_offset(buff);
        match net_nr {
            0x0800u16 => packet::Network::Ipv4Net(
                ipv4::Ipv4 { offset: net_offset }),
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
