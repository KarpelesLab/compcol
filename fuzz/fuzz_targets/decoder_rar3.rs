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
// and 1 flag byte:
//   bit 0: enable the standalone E8/E9 post-pass filter
//   bit 1: ... also translating E9 jumps
//   bit 2: solid-group mode — the payload becomes up to 4 members, each
//          introduced by a 5-byte header (2-byte LE chunk length + 3-byte
//          LE unpack size, capped to 256 KiB — 1 MiB per group); the
//          shared LZ window, tables, filter programs and PPMd model
//          persist across them. The outer 4-byte unpack prefix is unused
//          in this mode.

/// Feed one member's payload and drain it. Returns false when the decoder
/// errored (a fine outcome — the input is garbage; we only care that it
/// never panics or loops).
fn drive_member(dec: &mut Decoder, payload: &[u8]) -> bool {
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
            Err(_) => return false,
        }
        steps += 1;
        if steps > 4096 {
            // Defensive: pathological inputs shouldn't make us loop.
            return false;
        }
    }
    let mut steps = 0;
    loop {
        match dec.finish(&mut out) {
            Ok((p, status)) => {
                if matches!(status, compcol::Status::StreamEnd) {
                    return true;
                }
                if p.written == 0 {
                    return true;
                }
            }
            Err(_) => return false,
        }
        steps += 1;
        if steps > 4096 {
            return false;
        }
    }
}

fn drive(mut dec: Decoder, payload: &[u8]) {
    drive_member(&mut dec, payload);
}

fn drive_solid(mut payload: &[u8]) {
    let mut dec: Option<Decoder> = None;
    for _ in 0..4 {
        if payload.len() < 5 {
            return;
        }
        let (hdr, rest) = payload.split_at(5);
        let want = u16::from_le_bytes([hdr[0], hdr[1]]) as usize;
        let unpack = (u32::from_le_bytes([hdr[2], hdr[3], hdr[4], 0]) as u64) % (256 * 1024 + 1);
        let (chunk, rest) = rest.split_at(want.min(rest.len()));
        payload = rest;
        let d = match dec.as_mut() {
            None => dec.insert(Decoder::with_unpack_size(unpack).with_solid()),
            Some(d) => {
                if d.begin_solid_member(unpack).is_err() {
                    return;
                }
                d
            }
        };
        if !drive_member(d, chunk) {
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

    if prefix[4] & 4 != 0 {
        drive_solid(payload);
        return;
    }

    let mut dec = Decoder::with_unpack_size(unpack);
    if prefix[4] & 1 != 0 {
        dec = dec.with_e8_filter(prefix[4] & 2 != 0);
    }
    drive(dec, payload);
});
