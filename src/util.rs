
// printing
pub fn to_hex_string(bytes: &[u8]) -> String {
    let strs: Vec<String> = bytes.iter()
        .map(|b| format!("0x{:02X}", b))
        .collect();
    strs.join(", ")
}

pub fn print_hex_and_die(msg: &str, bytes: &[u8]) {
    let byte_str = to_hex_string(bytes);
    panic!("exiting: {}, while processing packet: [{}]", msg, byte_str);
}
