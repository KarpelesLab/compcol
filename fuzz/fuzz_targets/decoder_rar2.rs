#![no_main]
use compcol::Decoder as _;
use compcol::rar2::Decoder;
use libfuzzer_sys::fuzz_target;

// Smoke property: the decoder must not panic on arbitrary input.
// libfuzzer feeds us garbage bytes; we drive the decoder over them
// and discard the result. Any panic, abort, or undefined behavior
// trips the harness.
//
// RAR2 streams don't self-delimit — the decompressed length lives in
// the archive container's file header — so we read a 4-byte LE length
// prefix (capped to 1 MiB so a hostile size field can't make the
// harness itself allocate unbounded output). `decode` only buffers;
// the real decompression runs on the first `finish` call.
fn drive(mut dec: Decoder, payload: &[u8]) {
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
            // Defensive: pathological inputs shouldn't make us loop.
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
        // no-declared-size path with the whole input as payload.
        drive(Decoder::new(), data);
        return;
    };
    let raw = u32::from_le_bytes([len_bytes[0], len_bytes[1], len_bytes[2], len_bytes[3]]);
    let unpack = (raw as u64) % (1024 * 1024 + 1);

    drive(Decoder::with_unpack_size(unpack), payload);
});
