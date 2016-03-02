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

