#![no_main]
use compcol::{ContiguousDecoder, Decoder, Error, Status, factory};
use libfuzzer_sys::fuzz_target;

// Differential: a decoder with a contiguous mode must give the same result
// decoding into one buffer that doubles as its history as it gives through
// the ordinary windowed `decode` / `finish` calls.
//
// Input layout: byte 0 picks the decoder, byte 1 the input chunk size,
// byte 2 how the contiguous buffer grows; the rest is the stream.
//
// "Same result" is the same bytes and the same outcome class (clean end, or
// an error). The error variants may differ: an input with two defects can
// meet a different one first, as it already can between two chunkings of
// the windowed path.

const NAMES: &[&str] = &["lzma", "xz", "lzma2", "zstd"];
const MAX_OUTPUT: usize = 1 << 19;
const MAX_STEPS: usize = 1 << 16;

enum Outcome {
    End,
    Err(Error),
    /// The harness's own bound, not a decoder verdict.
    Bound,
}

/// The windowed decoder to compare against. Contiguous mode allocates no
/// dictionary, so by design it does not apply the limits that exist to
/// bound one (`lzma`'s `max_dict_size`, `zstd`'s `max_window_size`); lift
/// them here so both sides accept the same streams. The windowed side grows
/// its history with the output, which `MAX_OUTPUT` keeps small.
fn windowed_decoder(name: &str) -> Box<dyn Decoder> {
    match name {
        "lzma" => Box::new(compcol::lzma::Decoder::with_config(
            compcol::lzma::DecoderConfig::with_max_dict_size(compcol::lzma::MAX_DICT_SIZE),
        )),
        "zstd" => Box::new(compcol::zstd::Decoder::with_config(
            compcol::zstd::DecoderConfig::default().with_max_window_size(u64::MAX),
        )),
        _ => factory::decoder_by_name(name).expect("compiled in"),
    }
}

fn windowed(name: &str, data: &[u8]) -> (Vec<u8>, Outcome) {
    let mut dec = windowed_decoder(name);
    let mut out = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut pos = 0;
    for _ in 0..MAX_STEPS {
        let (p, status) = match dec.decode(&data[pos..], &mut buf) {
            Ok(r) => r,
            Err(e) => return (out, Outcome::Err(e)),
        };
        pos += p.consumed;
        out.extend_from_slice(&buf[..p.written]);
        if out.len() > MAX_OUTPUT {
            return (out, Outcome::Bound);
        }
        if status == Status::StreamEnd {
            return (out, Outcome::End);
        }
        if pos == data.len() && p.written == 0 {
            break;
        }
    }
    for _ in 0..MAX_STEPS {
        let (p, status) = match dec.finish(&mut buf) {
            Ok(r) => r,
            Err(e) => return (out, Outcome::Err(e)),
        };
        out.extend_from_slice(&buf[..p.written]);
        if out.len() > MAX_OUTPUT {
            return (out, Outcome::Bound);
        }
        if status == Status::StreamEnd {
            return (out, Outcome::End);
        }
        if p.written == 0 {
            break;
        }
    }
    (out, Outcome::Bound)
}

fn contiguous(name: &str, data: &[u8], in_chunk: usize, grow: usize) -> (Vec<u8>, Outcome) {
    let mut dec = factory::contiguous_decoder_by_name(name).expect("has a contiguous mode");
    // The decoder is shown a prefix of one of two buffers. Whenever it asks
    // for room the prefix moves to the other buffer, longer, and the one it
    // was in is scribbled over: the decoder may keep nothing that points
    // into a buffer it was given before. (Two fixed buffers rather than a
    // fresh allocation per step: thousands of large allocations per input
    // make the sanitizer's quarantine, not the decoder, run out of memory.)
    let cap = MAX_OUTPUT + (1 << 18) + grow;
    let mut bufs = [vec![0xA5u8; cap], vec![0xA5u8; cap]];
    let mut cur = 0usize;
    let mut len = grow;
    let mut filled = 0;
    let mut pos = 0;
    let mut finishing = false;
    let take = |bufs: &[Vec<u8>; 2], cur: usize, filled: usize| bufs[cur][..filled].to_vec();
    for _ in 0..MAX_STEPS {
        let out = &mut bufs[cur][..len];
        let r = if finishing {
            dec.finish_contiguous(out, filled)
        } else {
            let end = (pos + in_chunk).min(data.len());
            dec.decode_contiguous(&data[pos..end], out, filled)
        };
        let (p, status) = match r {
            Ok(r) => r,
            Err(e) => return (take(&bufs, cur, filled), Outcome::Err(e)),
        };
        assert!(filled + p.written <= len, "{name}: wrote past the buffer");
        pos += p.consumed;
        filled += p.written;
        if filled > MAX_OUTPUT {
            return (take(&bufs, cur, filled), Outcome::Bound);
        }
        match status {
            Status::StreamEnd => return (take(&bufs, cur, filled), Outcome::End),
            Status::OutputFull => {
                // Small steps while the buffer is small, to cut matches and
                // blocks at every position; geometric after that.
                let step = grow.max(len.saturating_sub(64 * 1024) / 4);
                len = (len + step).min(cap);
                let (a, b) = bufs.split_at_mut(1);
                let (from, to) = if cur == 0 {
                    (&mut a[0], &mut b[0])
                } else {
                    (&mut b[0], &mut a[0])
                };
                to[..filled].copy_from_slice(&from[..filled]);
                to[filled..].fill(0xA5);
                from.fill(0x5A);
                cur ^= 1;
            }
            Status::InputEmpty => {
                if pos == data.len() {
                    if finishing {
                        // `finish` asks for neither room nor an end: a stall.
                        panic!("{name}: finish_contiguous made no progress");
                    }
                    finishing = true;
                }
            }
        }
    }
    (take(&bufs, cur, filled), Outcome::Bound)
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let name = NAMES[data[0] as usize % NAMES.len()];
    let in_chunk = match data[1] {
        0 => usize::MAX / 2,
        n => n as usize,
    };
    // 1 byte .. ~256 KiB per growth step.
    let grow = 1usize << (data[2] % 19);
    let stream = &data[3..];

    let (want, w) = windowed(name, stream);
    let (got, c) = contiguous(name, stream, in_chunk, grow);
    match (&w, &c) {
        (Outcome::Bound, _) | (_, Outcome::Bound) => {}
        (Outcome::End, Outcome::End) => {
            assert!(
                want == got,
                "{name}: output differs ({} vs {})",
                want.len(),
                got.len()
            );
        }
        (Outcome::Err(_), Outcome::Err(_)) => {
            // Both reject. What was handed out before the error may differ
            // in length (the windowed path decodes ahead), never in content.
            let n = want.len().min(got.len());
            assert!(
                want[..n] == got[..n],
                "{name}: bytes before the error differ"
            );
        }
        (Outcome::End, Outcome::Err(e)) => {
            panic!(
                "{name}: windowed decoded {} bytes, contiguous failed with {e:?}",
                want.len()
            )
        }
        (Outcome::Err(e), Outcome::End) => {
            panic!(
                "{name}: windowed failed with {e:?}, contiguous decoded {} bytes",
                got.len()
            )
        }
    }
});
