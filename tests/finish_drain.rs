//! Cross-codec check of the `finish` drain contract.
//!
//! A decoder may swallow all of its input in one `decode` call while still
//! holding more decoded bytes than the caller's buffer takes (bzip2 buffers
//! a whole block, zstd a whole Compressed_Block, …). `Decoder::finish` is
//! documented as "call repeatedly until `StreamEnd`", so it must hand those
//! bytes out over several calls instead of reporting `UnexpectedEnd`. bzip2
//! used to fail this, which broke `vec::decompress_to_vec*` and
//! `io::DecoderWriter` on any block larger than their staging buffer.

#![cfg(all(feature = "factory", feature = "alloc"))]

use compcol::{Status, factory};

fn payload() -> Vec<u8> {
    // ~200 kB, compressible but not trivially so.
    let mut x: u32 = 1;
    (0..200_000u32)
        .map(|i| {
            x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            if i % 7 == 0 {
                (x >> 24) as u8
            } else {
                b"abcdefgh"[(i % 8) as usize]
            }
        })
        .collect()
}

#[test]
fn every_decoder_drains_pending_output_through_finish() {
    let plain = payload();
    let mut checked = 0;
    for &name in factory::names() {
        // Raw lh1/lh2 payloads carry no in-band end and need the length out
        // of band, which the by-name factory can't supply.
        if name == "lh1" || name == "lh2" {
            continue;
        }
        let Some(mut enc) = factory::encoder_by_name(name) else {
            continue;
        };
        let mut encoded = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        let mut c = 0;
        let mut unsupported = false;
        while c < plain.len() {
            match enc.encode(&plain[c..], &mut buf) {
                Ok((p, s)) => {
                    encoded.extend_from_slice(&buf[..p.written]);
                    c += p.consumed;
                    if s == Status::InputEmpty {
                        break;
                    }
                }
                Err(compcol::Error::Unsupported) => {
                    unsupported = true;
                    break;
                }
                Err(e) => panic!("{name}: encode failed: {e:?}"),
            }
        }
        if unsupported {
            continue; // decoder-only codec
        }
        loop {
            let (p, s) = enc
                .finish(&mut buf)
                .unwrap_or_else(|e| panic!("{name}: finish failed: {e:?}"));
            encoded.extend_from_slice(&buf[..p.written]);
            if s == Status::StreamEnd {
                break;
            }
        }

        // Hand over the whole stream with a small output buffer, then drain
        // only through `finish`.
        let mut dec = factory::decoder_by_name(name).unwrap();
        let mut small = vec![0u8; 4096];
        let mut out = Vec::new();
        let mut consumed = 0;
        let mut ended = false;
        while consumed < encoded.len() {
            let (p, s) = dec
                .decode(&encoded[consumed..], &mut small)
                .unwrap_or_else(|e| panic!("{name}: decode failed: {e:?}"));
            out.extend_from_slice(&small[..p.written]);
            consumed += p.consumed;
            if s == Status::StreamEnd {
                ended = true;
                break;
            }
        }
        while !ended {
            let (p, s) = dec
                .finish(&mut small)
                .unwrap_or_else(|e| panic!("{name}: finish failed: {e:?}"));
            out.extend_from_slice(&small[..p.written]);
            ended = s == Status::StreamEnd;
            assert!(ended || p.written > 0, "{name}: finish stalled");
        }
        assert!(out == plain, "{name}: round-trip mismatch");
        checked += 1;
    }
    assert!(checked > 0, "no round-trippable codec compiled in");
}
