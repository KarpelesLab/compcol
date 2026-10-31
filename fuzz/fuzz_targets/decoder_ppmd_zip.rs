#![no_main]
use compcol::Decoder as _;
use compcol::ppmd::ZipDecoder;
use libfuzzer_sys::fuzz_target;

// Smoke property: the ZIP method 98 (PPMd var. I) decoder must not panic
// on arbitrary input. The first byte picks the mode (known size or end
// marker); the memory field of the PPMd header is clamped to 4 MB so
// each run doesn't allocate up to 256 MB.
fuzz_target!(|data: &[u8]| {
    let Some((&mode, rest)) = data.split_first() else {
        return;
    };
    let mut input = rest.to_vec();
    if input.len() >= 2 {
        input[0] &= 0x3F;
        input[1] &= 0xF0;
    }
    let mut dec = if mode & 1 == 0 {
        ZipDecoder::new((mode as u64) << 8)
    } else {
        ZipDecoder::until_end_marker()
    };
    let mut out = vec![0u8; 64 * 1024];
    let mut consumed = 0;
    let mut steps = 0;
    while consumed < input.len() {
        match dec.decode(&input[consumed..], &mut out) {
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
