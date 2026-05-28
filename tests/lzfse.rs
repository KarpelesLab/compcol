//! Integration tests for the LZFSE decoder.
//!
//! LZFSE is decoder-only in this crate (encoder always returns
//! [`Error::Unsupported`]). These tests:
//!
//! - confirm the algorithm metadata and Encoder-side Unsupported contract;
//! - decode a hand-built minimal stream (`bvx-` literal block + `bvx$`);
//! - decode a hand-built `bvxn` (LZVN) fixture (literals-only `bvxn` for
//!   the ASCII string "hello world", and a 100-byte run);
//! - exercise streaming with 1-byte input chunking;
//! - reject truncated input without panicking;
//! - confirm garbage doesn't panic;
//! - confirm `reset()` puts the decoder back to AwaitMagic;
//! - confirm `bvx2` blocks return [`Error::Unsupported`] (documented gap).
//!
//! Canonical v0.3 port: every codec call returns `(Progress, Status)` and
//! loops dispatch on `Status` rather than inferring from byte counts.

#![cfg(feature = "lzfse")]

use compcol::lzfse::{Decoder, Encoder, Lzfse};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

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

// ─── encoder is permanently unsupported ──────────────────────────────────

#[test]
fn encoder_encode_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(
        enc.encode(b"hello", &mut out).unwrap_err(),
        Error::Unsupported
    );
}

#[test]
fn encoder_finish_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 16];
    assert_eq!(enc.finish(&mut out).unwrap_err(), Error::Unsupported);
}

#[test]
fn encoder_reset_is_a_no_op() {
    let mut enc = Encoder::new();
    enc.reset();
    let mut out = [0u8; 4];
    assert_eq!(enc.encode(b"x", &mut out).unwrap_err(), Error::Unsupported);
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

// ─── bvx2 (LZFSE v2) is documented Unsupported in this build ─────────────

#[test]
fn bvx2_block_returns_unsupported() {
    // Construct a stream that starts with bvx2 magic. The decoder should
    // read the magic, peek at the v2 header (need 28 bytes after magic
    // for the fixed-size portion), and then return Unsupported.
    let mut stream = b"bvx2".to_vec();
    // 28 bytes of arbitrary header bytes — content doesn't matter because
    // we return Unsupported before interpreting them.
    stream.extend_from_slice(&[0u8; 32]);

    let mut dec = Decoder::new();
    let mut buf = [0u8; 256];
    // Feed all input. Expect Err(Unsupported) at some point.
    let r = dec.decode(&stream, &mut buf);
    assert!(
        matches!(r, Err(Error::Unsupported)),
        "expected Unsupported on bvx2 block, got {:?}",
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
    fn boxed_encoder_is_unsupported() {
        use compcol::Error;
        let mut enc = factory::encoder_by_name("lzfse").unwrap();
        let mut out = [0u8; 16];
        assert_eq!(
            enc.encode(b"hello", &mut out).unwrap_err(),
            Error::Unsupported
        );
    }

    #[test]
    fn extension_is_lzfse() {
        assert_eq!(factory::extension("lzfse"), Some("lzfse"));
    }
}
