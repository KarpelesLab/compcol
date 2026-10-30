//! Integration tests for the LZFSE decoder.
//!
//! Decoder-side tests (the encoder has its own file, `lzfse_encoder.rs`):
//!
//! - confirm the algorithm metadata;
//! - decode a hand-built minimal stream (`bvx-` literal block + `bvx$`);
//! - decode a hand-built `bvxn` (LZVN) fixture (literals-only `bvxn` for
//!   the ASCII string "hello world", and a 100-byte run);
//! - exercise streaming with 1-byte input chunking;
//! - reject truncated input without panicking;
//! - confirm garbage doesn't panic;
//! - confirm `reset()` puts the decoder back to AwaitMagic;
//! - decode real multi-block `bvx2` streams from an independent encoder.
//!
//! Canonical v0.3 port: every codec call returns `(Progress, Status)` and
//! loops dispatch on `Status` rather than inferring from byte counts.

#![cfg(feature = "lzfse")]

use compcol::lzfse::{Decoder, Lzfse};
use compcol::{Algorithm, Decoder as _, Error, Status};

// ─── helpers ─────────────────────────────────────────────────────────────

/// Construct a `bvx-` (uncompressed) block: magic + u32_le(len) + payload.
fn make_uncompressed_block(payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"bvx-");
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(payload);
    b
}

/// EOS marker.
fn eos() -> Vec<u8> {
    b"bvx$".to_vec()
}

/// Construct a `bvxn` (LZVN) block from a hand-built LZVN payload.
fn make_lzvn_block(decoded_len: u32, payload: &[u8]) -> Vec<u8> {
    let mut b = Vec::new();
    b.extend_from_slice(b"bvxn");
    b.extend_from_slice(&decoded_len.to_le_bytes());
    b.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    b.extend_from_slice(payload);
    b
}

/// LZVN payload that encodes `text` as literals only (sml_l opcodes), with
/// an EOS terminator. Assumes `text.len() <= 15`.
fn lzvn_payload_literals_small(text: &[u8]) -> Vec<u8> {
    assert!(text.len() <= 15);
    let mut p = Vec::new();
    p.push(0xE0 | (text.len() as u8)); // sml_l with L = text.len()
    p.extend_from_slice(text);
    // EOS: 0x06 + 7 zero bytes.
    p.push(0x06);
    p.extend_from_slice(&[0; 7]);
    p
}

/// LZVN payload encoding `n` repetitions of byte `b` as several sml_l
/// opcodes (each emits up to 15 literals) followed by EOS. This is the
/// simplest valid LZVN payload of arbitrary length.
fn lzvn_payload_literals(b: u8, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut remaining = n;
    while remaining > 0 {
        let chunk = remaining.min(15);
        out.push(0xE0 | (chunk as u8));
        for _ in 0..chunk {
            out.push(b);
        }
        remaining -= chunk;
    }
    // EOS: 0x06 + 7 zero bytes.
    out.push(0x06);
    out.extend_from_slice(&[0; 7]);
    out
}

/// Drive `decoder.decode` followed by `decoder.finish`, accumulating output.
fn drive_to_end(dec: &mut Decoder, input: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; 256];
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, status) = dec.decode(&input[consumed..], &mut buf).unwrap();
        consumed += p.consumed;
        out.extend_from_slice(&buf[..p.written]);
        match status {
            Status::OutputFull => continue,
            Status::InputEmpty => break,
            Status::StreamEnd => {
                return out;
            }
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    out
}

// ─── algorithm metadata ──────────────────────────────────────────────────

#[test]
fn algorithm_name_is_lzfse() {
    assert_eq!(<Lzfse as Algorithm>::NAME, "lzfse");
}

#[test]
fn lzfse_algorithm_factory_produces_codec() {
    let _enc = <Lzfse as Algorithm>::encoder();
    let _dec = <Lzfse as Algorithm>::decoder();
}

#[test]
fn decoder_new_does_not_panic() {
    let _ = Decoder::new();
}

// ─── empty / pure-EOS streams ────────────────────────────────────────────

#[test]
fn pure_eos_stream_decodes_to_empty() {
    let stream = eos();
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream);
    assert_eq!(out, b"");
}

// ─── uncompressed (bvx-) block ───────────────────────────────────────────

const HELLO_WORLD: &[u8] = b"hello world";

#[test]
fn uncompressed_hello_world() {
    let mut stream = make_uncompressed_block(HELLO_WORLD);
    stream.extend_from_slice(&eos());
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream);
    assert_eq!(out, HELLO_WORLD);
}

#[test]
fn uncompressed_empty_payload() {
    let mut stream = make_uncompressed_block(b"");
    stream.extend_from_slice(&eos());
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream);
    assert_eq!(out, b"");
}

#[test]
fn multiple_uncompressed_blocks() {
    let mut stream = make_uncompressed_block(b"hello ");
    stream.extend_from_slice(&make_uncompressed_block(b"world"));
    stream.extend_from_slice(&eos());
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream);
    assert_eq!(out, b"hello world");
}

// ─── streaming: one byte at a time ───────────────────────────────────────

#[test]
fn uncompressed_one_byte_at_a_time() {
    let mut stream = make_uncompressed_block(HELLO_WORLD);
    stream.extend_from_slice(&eos());
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = [0u8; 16];
    let mut consumed = 0;
    // Feed one byte at a time. Each call may or may not produce output.
    while consumed < stream.len() {
        let (p, status) = dec
            .decode(&stream[consumed..consumed + 1], &mut buf)
            .unwrap();
        consumed += p.consumed;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
    }
    // Drain remaining output via finish.
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
    }
    assert_eq!(out, HELLO_WORLD);
}

// ─── bvxn (LZVN) block ──────────────────────────────────────────────────

#[test]
fn lzvn_hello_world_literals_only() {
    let payload = lzvn_payload_literals_small(HELLO_WORLD);
    let mut stream = make_lzvn_block(HELLO_WORLD.len() as u32, &payload);
    stream.extend_from_slice(&eos());
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream);
    assert_eq!(out, HELLO_WORLD);
}

#[test]
fn lzvn_literal_then_sml_d_match() {
    // Hand-built payload exercising the SmlD opcode:
    //   sml_l L=6 "ABCDEF" → out = "ABCDEF"
    //   SmlD L=0 M=3 D=3   → match copies "DEF" from out[3..6] → "ABCDEFDEF"
    //   EOS
    // Expected output: "ABCDEFDEF" (9 bytes).
    let mut payload = Vec::new();
    payload.push(0xE6); // sml_l with L=6
    payload.extend_from_slice(b"ABCDEF");
    payload.push(0x00); // SmlD opcode (L=0, M_raw=0 → M=3, D_high=0)
    payload.push(0x03); // D_low = 3
    payload.push(0x06); // EOS
    payload.extend_from_slice(&[0; 7]);

    let mut stream = make_lzvn_block(9, &payload);
    stream.extend_from_slice(&eos());

    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream);
    assert_eq!(out, b"ABCDEFDEF");
}

#[test]
fn lzvn_sml_m_reuses_previous_distance() {
    // Hand-built payload exercising SmlM (uses d_prev):
    //   sml_l L=4 "ABCD" → out = "ABCD"
    //   SmlD L=0 M=3 D=2 → match copies "CD" + "C" from pos 2 → "ABCD" + "CDC" = "ABCDCDC"
    //                       d_prev becomes 2
    //   SmlM M=4         → match copies 4 bytes at d=2 (d_prev) → uses overlap, splats "CDCD"
    //                       out = "ABCDCDC" + 4 bytes from pos out.len()-2=5 onward = "CDCDCDC" ...
    //                       Wait: out.len()=7, src_pos = 7-2 = 5. byte-by-byte:
    //                         i=0: out[5]='C', push → "ABCDCDC" + "C" = "ABCDCDCC", len=8
    //                         i=1: out[6]='C', push → ...C, len=9
    //                         i=2: out[7]='C', push → ...C, len=10
    //                         i=3: out[8]='C', push → ...C, len=11
    //                       Hmm — let me redo: out before SmlM = "ABCDCDC", src_pos = 5.
    //                       out[5] = 'D' (positions: A B C D C D C, indices 0..6).
    //                       So i=0: out[5]='D', push 'D' → out = "ABCDCDCD", len=8
    //                          i=1: out[6]='C', push 'C' → "ABCDCDCDC", len=9
    //                          i=2: out[7]='D', push 'D' → "ABCDCDCDCD", len=10
    //                          i=3: out[8]='C', push 'C' → "ABCDCDCDCDC", len=11
    //   EOS
    let mut payload = Vec::new();
    payload.push(0xE4); // sml_l L=4
    payload.extend_from_slice(b"ABCD");
    payload.push(0x00); // SmlD L=0 M_raw=0 (M=3) D_high=0
    payload.push(0x02); // D_low=2 → D=2
    payload.push(0xF4); // SmlM, M = 0xF4 & 0xF = 4
    payload.push(0x06); // EOS
    payload.extend_from_slice(&[0; 7]);

    let mut stream = make_lzvn_block(11, &payload);
    stream.extend_from_slice(&eos());

    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream);
    assert_eq!(out, b"ABCDCDCDCDC");
}

#[test]
fn lzvn_100_capital_a() {
    let expected = vec![b'A'; 100];
    let payload = lzvn_payload_literals(b'A', 100);
    let mut stream = make_lzvn_block(100u32, &payload);
    stream.extend_from_slice(&eos());
    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream);
    assert_eq!(out, expected);
}

#[test]
fn lzvn_one_byte_at_a_time() {
    let payload = lzvn_payload_literals_small(HELLO_WORLD);
    let mut stream = make_lzvn_block(HELLO_WORLD.len() as u32, &payload);
    stream.extend_from_slice(&eos());

    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = [0u8; 16];
    let mut consumed = 0;
    while consumed < stream.len() {
        let (p, status) = dec
            .decode(&stream[consumed..consumed + 1], &mut buf)
            .unwrap();
        consumed += p.consumed;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
    }
    assert_eq!(out, HELLO_WORLD);
}

// ─── bvx2 (LZFSE v2) is now decoded ──────────────────────────────────────
//
// The bvx2 decoder itself is validated by round-trip against this crate's
// own spec-conformant v2 encoder in `src/lzfse/lzfse_v2.rs` (in-crate unit
// tests, which can reach the `#[cfg(test)]` encoder helper). From the public
// integration surface we only assert that a *malformed* bvx2 header is
// rejected cleanly (no panic, no Unsupported) — proving the v2 arm is wired
// in and reaches real header parsing rather than the old Unsupported stub.

#[test]
fn bvx2_malformed_header_rejected_without_panic() {
    // A bvx2 magic followed by 32 zero header bytes is not a valid v2 block
    // (the frequency tables would not sum to the FSE state counts). The
    // decoder must reject it as Corrupt rather than returning Unsupported or
    // panicking.
    let mut stream = b"bvx2".to_vec();
    stream.extend_from_slice(&[0u8; 32]);

    let mut dec = Decoder::new();
    let mut buf = [0u8; 256];
    let r = dec.decode(&stream, &mut buf);
    assert!(
        matches!(r, Err(Error::Corrupt) | Err(Error::UnexpectedEnd)),
        "expected Corrupt/UnexpectedEnd on malformed bvx2 block, got {:?}",
        r
    );
}

// ─── truncated input ─────────────────────────────────────────────────────

#[test]
fn truncated_magic_does_not_panic() {
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    // 3 bytes — not enough for magic.
    let (p, status) = dec.decode(b"bvx", &mut buf).unwrap();
    assert_eq!(p.consumed, 3);
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::InputEmpty));
    // finish: should report UnexpectedEnd since we have a partial block.
    let r = dec.finish(&mut buf);
    assert_eq!(r, Err(Error::UnexpectedEnd));
}

#[test]
fn truncated_uncompressed_payload_does_not_panic() {
    // bvx- magic + length=10, but only 3 bytes of payload before EOI.
    let mut stream = b"bvx-".to_vec();
    stream.extend_from_slice(&10u32.to_le_bytes());
    stream.extend_from_slice(b"abc");
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let _ = dec.decode(&stream, &mut buf);
    let r = dec.finish(&mut buf);
    assert!(matches!(r, Err(Error::UnexpectedEnd) | Err(Error::Corrupt)));
}

#[test]
fn garbage_magic_rejected() {
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    let r = dec.decode(b"GARB", &mut buf);
    assert_eq!(r, Err(Error::BadHeader));
}

// ─── reset behaviour ─────────────────────────────────────────────────────

#[test]
fn reset_returns_to_await_magic() {
    let mut stream = make_uncompressed_block(HELLO_WORLD);
    stream.extend_from_slice(&eos());

    let mut dec = Decoder::new();
    let out = drive_to_end(&mut dec, &stream);
    assert_eq!(out, HELLO_WORLD);

    dec.reset();

    // Decode again, get the same result.
    let out2 = drive_to_end(&mut dec, &stream);
    assert_eq!(out2, HELLO_WORLD);
}

#[test]
fn reset_after_error_recovers() {
    let mut dec = Decoder::new();
    let mut buf = [0u8; 16];
    // Garbage magic poisons the decoder.
    assert_eq!(dec.decode(b"GARB", &mut buf), Err(Error::BadHeader));
    // Without reset, further calls should error.
    assert!(dec.decode(b"x", &mut buf).is_err());
    dec.reset();
    // After reset, we should be able to decode a fresh valid stream.
    let stream = eos();
    let out = drive_to_end(&mut dec, &stream);
    assert_eq!(out, b"");
}

// ─── factory (only if the feature is enabled) ────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_lzfse_encoder_and_decoder() {
        assert!(factory::encoder_by_name("lzfse").is_some());
        assert!(factory::decoder_by_name("lzfse").is_some());
    }

    #[test]
    fn lookup_unknown() {
        assert!(factory::encoder_by_name("not-a-real-lzfse").is_none());
        assert!(factory::decoder_by_name("not-a-real-lzfse").is_none());
    }

    #[test]
    fn names_contains_lzfse() {
        assert!(factory::names().contains(&"lzfse"));
    }

    #[test]
    fn boxed_encoder_round_trips() {
        let data = b"boxed lzfse encoder, boxed lzfse encoder".repeat(300);
        let mut enc = factory::encoder_by_name("lzfse").unwrap();
        let mut packed = Vec::new();
        let mut buf = vec![0u8; 1 << 16];
        let (p, _) = enc.encode(&data, &mut buf).unwrap();
        assert_eq!(p.consumed, data.len());
        packed.extend_from_slice(&buf[..p.written]);
        loop {
            let (p, s) = enc.finish(&mut buf).unwrap();
            packed.extend_from_slice(&buf[..p.written]);
            if s == compcol::Status::StreamEnd {
                break;
            }
        }
        assert!(packed.len() < data.len() / 10);
        let mut dec = factory::decoder_by_name("lzfse").unwrap();
        let mut out = vec![0u8; data.len() + 1];
        let (p, s) = dec.decode(&packed, &mut out).unwrap();
        assert_eq!(s, compcol::Status::StreamEnd);
        assert_eq!(&out[..p.written], &data[..]);
    }

    #[test]
    fn extension_is_lzfse() {
        assert_eq!(factory::extension("lzfse"), Some("lzfse"));
    }
}

// ─── bvx2 streams from an independent encoder ───────────────────────────

/// Input of `fixtures/lzfse/sample_400000.lzfse`: a small-alphabet text with
/// back-references up to 200 KB away, so the stream holds several `bvx2`
/// blocks whose matches reach into earlier blocks.
fn lzfse_sample(n: usize) -> Vec<u8> {
    let mut s = 0x9E37_79B9_7F4A_7C15u64;
    let mut v: Vec<u8> = Vec::with_capacity(n);
    while v.len() < n {
        s ^= s << 13;
        s ^= s >> 7;
        s ^= s << 17;
        if v.len() > 1000 && s.is_multiple_of(4) {
            let d = 1 + ((s >> 8) as usize) % v.len().min(200_000);
            let l = 4 + ((s >> 40) as usize) % 200;
            let st = v.len() - d;
            for i in 0..l {
                let b = v[st + i % d];
                v.push(b);
            }
        } else {
            v.push(b"abcdefgh ijk\n"[((s >> 20) as usize) % 13]);
        }
    }
    v.truncate(n);
    v
}

/// Decode with `in_chunk`-byte input slices and an `out_chunk`-byte buffer.
fn decode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    decode_chunked_consumed(input, in_chunk, out_chunk).0
}

/// [`decode_chunked`], also returning the total input reported consumed.
fn decode_chunked_consumed(input: &[u8], in_chunk: usize, out_chunk: usize) -> (Vec<u8>, usize) {
    let mut dec = Lzfse::decoder();
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    let mut pos = 0;
    loop {
        let end = (pos + in_chunk).min(input.len());
        let (p, status) = dec.decode(&input[pos..end], &mut buf).unwrap();
        pos += p.consumed;
        out.extend_from_slice(&buf[..p.written]);
        if status == Status::StreamEnd {
            return (out, pos);
        }
        assert!(p.consumed > 0 || p.written > 0, "decoder stalled at {pos}");
    }
}

/// Bytes after the `bvx$` end-of-stream marker belong to the caller:
/// `decode` must not report them as consumed, whatever the chunking.
#[test]
fn trailing_bytes_after_eos_are_not_consumed() {
    let fixture = include_bytes!("fixtures/lzfse/sample_400000.lzfse");
    let mut stream = fixture.to_vec();
    stream.extend_from_slice(b"NEXT-FILE-DATA");
    for (in_chunk, out_chunk) in [
        (1, 1 << 20),
        (7, 333),
        (stream.len(), 1 << 20),
        (stream.len(), 1000),
    ] {
        let (out, consumed) = decode_chunked_consumed(&stream, in_chunk, out_chunk);
        assert_eq!(out, lzfse_sample(400_000));
        assert_eq!(
            consumed,
            fixture.len(),
            "in_chunk={in_chunk} out_chunk={out_chunk}"
        );
    }
}

/// Real `bvx2` streams (produced by the `lzfse_rust` crate, which is
/// validated against Apple's reference library) used to be rejected as
/// `Corrupt`: the decoder spread FSE table slots zstd-style, read the
/// payload bits LSB-first, swapped the state/extra-bit split of L/M/D
/// fields, emitted the literal stream's padding as output, and refused
/// match distances reaching into earlier blocks.
#[test]
fn bvx2_reference_multi_block_stream() {
    let fixture = include_bytes!("fixtures/lzfse/sample_400000.lzfse");
    let expected = lzfse_sample(400_000);
    assert_eq!(decode_chunked(fixture, usize::MAX / 2, 1 << 20), expected);
    assert_eq!(decode_chunked(fixture, 1, 1), expected);
    assert_eq!(decode_chunked(fixture, 4093, 777), expected);
}

#[test]
fn bvx2_reference_zeros() {
    let fixture = include_bytes!("fixtures/lzfse/zeros_300000.lzfse");
    assert_eq!(
        decode_chunked(fixture, 1 << 20, 1 << 20),
        vec![0u8; 300_000]
    );
    assert_eq!(decode_chunked(fixture, 1, 4096), vec![0u8; 300_000]);
}
