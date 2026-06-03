#![no_main]
use compcol::lzah::{DecoderConfig, Lzah};
use compcol::{Algorithm as _, Decoder as _};
use libfuzzer_sys::fuzz_target;

// Smoke property: the decoder must not panic on arbitrary input.
// libfuzzer feeds us garbage bytes; we drive the decoder over them
// and discard the result. Any panic, abort, or undefined behavior
// trips the harness.
//
// StuffIt method-5 (LZAH) streams carry no in-band end marker: the
// decoder needs the uncompressed length out of band. A plain
// `decoder()` returns `Unsupported` on any non-empty payload and never
// exercises the LZ + adaptive-Huffman decode loop. So we read a 4-byte
// LE length prefix from the fuzz input, cap it to 256 KiB, and feed the
// rest as the payload via `decoder_with(DecoderConfig::with_len(n))`.
fuzz_target!(|data: &[u8]| {
    let (len_bytes, payload) = if data.len() >= 4 {
        data.split_at(4)
    } else {
        return;
    };
    let raw = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
    let n = (raw as usize) % (256 * 1024 + 1);

    let mut dec = Lzah::decoder_with(DecoderConfig::with_len(n));
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
});
