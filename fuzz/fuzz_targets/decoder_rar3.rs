#![no_main]
use compcol::Decoder as _;
use compcol::rar3::Decoder;
use libfuzzer_sys::fuzz_target;

// Smoke property: the decoder must not panic on arbitrary input.
// libfuzzer feeds us garbage bytes; we drive the decoder over them
// and discard the result. Any panic, abort, or undefined behavior
// trips the harness.
//
// RAR3 streams don't carry their uncompressed length in-band — it
// lives in the archive container's file header — so we read a 5-byte
// prefix: 4 LE bytes for the unpack size (capped to 1 MiB so a hostile
// size field can't make the harness itself allocate unbounded output)
// and 1 flag byte driving the optional standalone E8/E9 post-pass
// filter (bit 0 enables it, bit 1 also translates E9 jumps).
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
    let (prefix, payload) = if data.len() >= 5 {
        data.split_at(5)
    } else {
        // Too short to carry a prefix: still fuzz the no-declared-size
        // path with the whole input as payload.
        drive(Decoder::new(), data);
        return;
    };
    let raw = u32::from_le_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]);
    let unpack = (raw as u64) % (1024 * 1024 + 1);

    let mut dec = Decoder::with_unpack_size(unpack);
    if prefix[4] & 1 != 0 {
        dec = dec.with_e8_filter(prefix[4] & 2 != 0);
    }
    drive(dec, payload);
});
