#![no_main]
//! All-decoders dispatch target. Byte 0 selects the algorithm; the
//! remaining bytes are fed to that decoder. Useful for catching cross-
//! algorithm regressions in shared building blocks (bit reader,
//! Huffman, FSE primitives, etc.) without having to maintain 20
//! separate corpora.

use compcol::factory;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    let names = factory::names();
    let pick = data[0] as usize % names.len();
    let name = names[pick];
    let Some(mut dec) = factory::decoder_by_name(name) else {
        return;
    };
    let payload = &data[1..];
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
