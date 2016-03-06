use super::eth;
use super::ipv4;
use super::ipv6;
use super::tcp;

// packets
pub struct Packet {
    pub data: Vec<u8>,
    pub len: usize,
    pub link: Link,
    pub net: Network,
//    trans: T
}

impl Packet {
    fn new(data: Vec<u8>, len: usize, link: Link, net: Network) -> Packet {
        Packet {
            data:  data, // the actual packet data
            len:   len, // length of the packet, as reported by backend
            link:  link, // link layer type and embedded offset
            net:   net  // network layer type and embedded offset
//            trans: trans // link layer type and embedded offset
        }
    }
}

pub fn make_eth_packet(data: Vec<u8>, len:usize) -> Packet {
    make_packet(data, Link::EthLink(eth::Eth{offset: 0}), len)
}

fn make_packet(data: Vec<u8>, link: Link, len: usize) -> Packet {
    let network = get_network_from_data(&data[..], &link);
    // let transport = get_transport_from_data(&data[..], network);
    Packet::new(data, len, link, network)
}

fn get_network_from_data(data: &[u8], link: &Link) -> Network {
    match link {
        &Link::EthLink(ref eth) => eth.get_network(&data[eth.offset..])
    }
}

fn get_transport_from_data(data: &[u8], net: &Network) -> Transport {
    match net {
        &Network::Ipv4Net(ref net) => net.get_transport(data),
        &Network::Ipv6Net(ref net) => net.get_transport(data),
    }
}

// link layer
pub enum Link {
    EthLink(eth::Eth)
}

pub trait HasLinkLayer {
    fn get_network(&self, data: &[u8]) -> Network;
    fn get_payload_offset(&self, data: &[u8]) -> usize;
}

// network layer
pub enum Network {
    Ipv4Net(ipv4::Ipv4),
    Ipv6Net(ipv6::Ipv6)
}

pub trait HasNetworkLayer {
    fn get_transport(&self, data: &[u8]) -> Transport;
    fn get_payload_offset(&self, data: &[u8]) -> usize;
}

// transport layer
pub enum Transport {
    TcpTrans(tcp::Tcp)
}


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
        0x04, 0x00, 0x00, 0x00, 0xFF, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0xFB);

    let icmp6_echo_packet = vec!(

        // eth
        0x33, 0x33, 0xFF, 0x00, 0x00, 0x01,
        0xC6, 0xEE, 0x04, 0xA6, 0x0F, 0x6A,
        0x86, 0xDD,

        // ipv6
        0x60, 0x00, 0x00, 0x00,
        0x00, 0x20, 0x3A, 0xFF,

        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x02,

        0xFF, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x01,
        0xFF, 0x00, 0x00, 0x01,

        0x87, 0x00, 0x9E, 0x9A,
        0x00, 0x00, 0x00, 0x00,

        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        0x01, 0x01, 0xC6, 0xEE, 0x04, 0xA6, 0x0F, 0x6A);
}
