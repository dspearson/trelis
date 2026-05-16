#![no_main]
use libfuzzer_sys::fuzz_target;
use trelis_wire::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut dec = Decoder::new(data);
    let _ = dec.read_u8();
    let _ = dec.read_u16();
    let _ = dec.read_u32();
    let _ = dec.read_u64();
    let _ = dec.read_bytes(data.len() / 2);
    let _ = dec.read_length_prefixed();
});
