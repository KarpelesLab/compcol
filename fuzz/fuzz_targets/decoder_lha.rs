#![no_main]
use compcol::Decoder as _;
use compcol::lha::{DecoderConfig, Lh1, Lh5};
use libfuzzer_sys::fuzz_target;

// Smoke property: the decoder must not panic on arbitrary input.
// libfuzzer feeds us garbage bytes; we drive the decoder over them
// and discard the result. Any panic, abort, or undefined behavior
// trips the harness.
//
// LHA methods come in two flavors here. The static-Huffman methods
// (lh4..lh7, e.g. `Lh5`) self-delimit and can be fuzzed in finish-mode
// with the default (no-length) decoder. The dynamic `lh1` method has no
// in-band end marker, so it returns `Unsupported` without an out-of-band
// length — to actually exercise its decode loop we must supply one via
// `DecoderConfig::with_len`. We read a 4-byte LE length prefix, cap it to
// 256 KiB, fuzz `Lh5` both ways and `Lh1` with the length.
fn drive<A: compcol::Algorithm<DecoderConfig = DecoderConfig>>(cfg: DecoderConfig, payload: &[u8]) {
    let mut dec = A::decoder_with(cfg);
    let mut out = vec![0u8; 64 * 1024];
    let mut consumed = 0;
    let mut steps = 0;
    while consumed < payload.len() {
        match dec.decode(&payload[consumed..], &mut out) {
            Ok((p, _)) => {
                if p.consumed == 0 && p.written == 0 {
                    break;
                }
                consumed += p.consumed;
            }
            Err(_) => return,
        }
        steps += 1;
        if steps > 4096 {
            return;
        }
    }
    let mut steps = 0;
    while let Ok((p, status)) = dec.finish(&mut out) {
        if matches!(status, compcol::Status::StreamEnd) {
            return;
        }
        if p.written == 0 {
            return;
        }
        steps += 1;
        if steps > 4096 {
            return;
        }
    }
}

fuzz_target!(|data: &[u8]| {
    let (len_bytes, payload) = if data.len() >= 4 {
        data.split_at(4)
    } else {
        // Too short to carry a length prefix: still fuzz the
        // finish-mode static path with the whole input as payload.
        drive::<Lh5>(DecoderConfig::default(), data);
        return;
    };
    let raw = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
    let n = (raw as usize) % (256 * 1024 + 1);

    // Static-Huffman lh5, finish-mode (no length supplied).
    drive::<Lh5>(DecoderConfig::default(), payload);
    // Static-Huffman lh5 with an out-of-band length.
    drive::<Lh5>(DecoderConfig::with_len(n), payload);
    // Dynamic lh1 needs the length to enter its decode loop.
    drive::<Lh1>(DecoderConfig::with_len(n), payload);
});
