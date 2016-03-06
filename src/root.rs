extern crate libc;
use std::io;
use libc::{uid_t, c_int};

// root things

// print_euid();
// let _ = set_reuid(0, unsafe { getuid() });
// print_euid();
// let old_euid = unsafe { geteuid() };
// let _ = set_reuid(0,0);
// let _ = set_reuid(0,old_euid);

extern {
    fn setreuid(ruid: uid_t, euid: uid_t) -> c_int;
    fn geteuid() -> uid_t;
    fn getuid() -> uid_t;
}

fn set_reuid(ruid: uid_t, euid: uid_t) {
    match unsafe { setreuid(ruid, euid) } {
        0  => (),
        -1 => panic!("{}", io::Error::last_os_error()),
        _  => unreachable!()
    }
}

fn print_euid() {
    let uid = unsafe { geteuid() };
    println!("uid is: {}", uid);
}   


pub fn condescend() {
    set_reuid(0, unsafe { getuid() });
}

pub struct Root {
    euid: uid_t
}

impl Root {
    pub fn new() -> Self {
        let euid = unsafe { geteuid() };
        set_reuid(0, 0);
        Root { euid: euid }
    }

    fn drop(&self) {
        set_reuid(0, self.euid)
    }
}
