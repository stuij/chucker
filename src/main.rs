#![feature(plugin)]
#![plugin(net_bits)]

extern crate libc;
extern crate tuntap;

mod packet;
mod util;
mod root;

use std::time::Duration;
use std::thread;

use packet::pkt;
use packet::eth;

// mainzy
fn main() {
    root::condescend();
    let as_root = root::Root::new();

    let mut tap = tuntap::TunTap::create_named_from_address(
        tuntap::Tap, "tap0", "10.0.0.1"
    );

    // thread::sleep(Duration::from_millis(2000000));
    loop {

        let mut buffer = vec![0u8; MTU_SIZE];
        let len = tap.read(&mut buffer).unwrap();
        println!("packet in len: {} data: {}", len,
                 util::to_hex_string(&buffer[..len]));

        let mut packet = pkt::make_eth_packet(buffer, len);

        match packet.net {
            pkt::Network::Ipv6Net(ref mut ipv6) => {
                // eth.get_network(&data[eth.offset..]);
                let data = &mut packet.data[ipv6.offset..];
                let src = ipv6.get_src(data);
                let dst = ipv6.get_dst(data);

                ipv6.set_src(data, dst);
                ipv6.set_dst(data, src)
            },
            pkt::Network::Ipv4Net(ref mut ipv4) => {
                // eth.get_network(&data[eth.offset..]);
                let data = &mut packet.data[ipv4.offset..];
                let src = ipv4.get_src(data);
                let dst = ipv4.get_dst(data);

                ipv4.set_src(data, dst);
                ipv4.set_dst(data, src)
            }
        }
//        println!("packet out len: {} data: {}",
//                 packet.len,
//                 util::to_hex_string(&packet.data[..packet.len]));
        let res = tap.write(&packet.data[..packet.len]);
    }
}
