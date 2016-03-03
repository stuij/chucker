#![feature(plugin)]
#![feature(slice_bytes)]
#![feature(log_syntax)]
#![plugin(net_bits)]
#![allow(dead_code)]

mod packet;
use packet::pkt;
use packet::eth;

extern crate libc;
extern crate tuntap;
extern crate byteorder;

use std::time::Duration;
use std::thread;

pub use libc::{uid_t, c_int};
use std::io;
use std::ffi::CString;


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


// mainzy
fn main() {
    print_euid();
    let _ = set_reuid(0, unsafe { getuid() });
    print_euid();

    let old_euid = unsafe { geteuid() };
    let _ = set_reuid(0,0);

    // let _ = set_reuid(0,old_euid);
    let mut tap = tuntap::TunTap::create_named_from_address(
        tuntap::Tap,
        tuntap::Ipv6,
        &CString::new("tap0").unwrap(),
        CString::new("10.0.0.1").unwrap()
    );
    // tap.add_address(CString::new("10.0.0.1").unwrap());
    // panic!("done");
    // thread::sleep(Duration::from_millis(2000000));
    loop {

        let mut buffer = vec![0u8; MTU_SIZE];
        let len = tap.read(&mut buffer).unwrap();
        println!("packet in len: {} data: {}", len, to_hex_string(&buffer[..len]));

        let mut packet = pkt::make_eth_packet(buffer, len);

        match packet.net {
            pkt::Network::Ipv6Net(ref mut ipv6) => {
                // eth.get_network(&data[eth.offset..]);
                let data = &mut packet.data[ipv6.offset..];
                let src = ipv6.get_src(data);
                let dst = ipv6.get_dst(data);

                ipv6.set_src(data, dst);
                ipv6.set_dst(data, src)
            }
            _ => panic!("ipv4 not covered")
        }
//        println!("packet out len: {} data: {}",
//                 packet.len,
//                 to_hex_string(&packet.data[..packet.len]));
        let res = tap.write(&packet.data[..packet.len]);
    }
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
        0x04, 0x00, 0x00, 0x00, 0xFF, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFB);

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

        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x01, 0x01, 0xC6, 0xEE, 0x04, 0xA6, 0x0F, 0x6A);
}

