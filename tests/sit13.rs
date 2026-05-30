//! Integration tests for the StuffIt method-13 codec.
//!
//! This build ships the well-defined building blocks (bit reader,
//! Kraft-validated Huffman, bounds-checked LZSS window — all unit-tested
//! inside `src/sit13/`) but returns [`Error::Unsupported`] for the payload
//! decode, and the encoder is permanently `Unsupported`. The format is
//! proprietary/undocumented (only an LGPL reverse-engineering exists, which
//! this MIT crate must not copy) and has no public fixtures, so a decoder
//! could be neither derived nor validated. See `src/sit13/mod.rs`.
//!
//! These tests cover the public surface:
//!
//! - algorithm metadata + factory shape;
//! - encoder permanently `Unsupported`;
//! - the special case of an explicitly-empty member (`unpack_size == 0`),
//!   which "decodes" to nothing without touching the unimplemented codec;
//! - a non-empty / unspecified-length payload returns `Unsupported`;
//! - poisoned-state recovery via `reset`;
//! - factory by-name lookup (gated behind the `factory` feature).

#![cfg(feature = "sit13")]

use compcol::sit13::{Decoder, Encoder, Sit13};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── algorithm metadata ──────────────────────────────────────────────────

#[test]
fn algorithm_name_is_sit13() {
    assert_eq!(<Sit13 as Algorithm>::NAME, "sit13");
}

#[test]
fn algorithm_factory_constructs_codec() {
    let _enc = <Sit13 as Algorithm>::encoder();
    let _dec = <Sit13 as Algorithm>::decoder();
}

#[test]
fn decoder_constructors_do_not_panic() {
    let _ = Decoder::new();
    let _ = Decoder::with_unpack_size(0);
    let _ = Decoder::with_unpack_size(1234);
    let _ = Decoder::default();
}

// ─── encoder is permanently unsupported ──────────────────────────────────

#[test]
fn encoder_encode_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 32];
    assert_eq!(enc.encode(b"hello", &mut out), Err(Error::Unsupported));
}

#[test]
fn encoder_finish_is_unsupported() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 32];
    assert_eq!(enc.finish(&mut out), Err(Error::Unsupported));
}

#[test]
fn encoder_reset_is_noop() {
    let mut enc = Encoder::new();
    enc.reset();
    let mut out = [0u8; 32];
    assert_eq!(enc.encode(b"x", &mut out), Err(Error::Unsupported));
}

// ─── empty member decodes to nothing ─────────────────────────────────────

#[test]
fn empty_member_decodes_to_empty_via_decode() {
    let mut dec = Decoder::with_unpack_size(0);
    let mut out = [0u8; 16];
    // No payload bytes; the decoder reports end-of-stream straight away.
    let (p, status) = dec.decode(&[], &mut out).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(p.consumed, 0);
    assert_eq!(status, Status::StreamEnd);
}

#[test]
fn empty_member_decodes_to_empty_via_finish() {
    let mut dec = Decoder::with_unpack_size(0);
    let mut out = [0u8; 16];
    let (p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::StreamEnd);
    // Subsequent finish stays terminal, no panic.
    let (p2, status2) = dec.finish(&mut out).unwrap();
    assert_eq!(p2.written, 0);
    assert_eq!(status2, Status::StreamEnd);
}

#[test]
fn empty_member_ignores_trailing_input() {
    // Even if the caller hands bytes, an empty member produces nothing.
    let mut dec = Decoder::with_unpack_size(0);
    let mut out = [0u8; 16];
    let (p, status) = dec.decode(&[0xAA, 0xBB, 0xCC], &mut out).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::StreamEnd);
}

// ─── non-empty / unspecified payload is unsupported ───────────────────────

#[test]
fn unspecified_length_payload_is_unsupported() {
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    assert_eq!(
        dec.decode(&[0x00, 0x01, 0x02], &mut out),
        Err(Error::Unsupported)
    );
}

#[test]
fn nonempty_member_payload_is_unsupported() {
    let mut dec = Decoder::with_unpack_size(42);
    let mut out = [0u8; 16];
    assert_eq!(dec.decode(&[0xFF; 8], &mut out), Err(Error::Unsupported));
}

#[test]
fn payload_finish_is_unsupported() {
    let mut dec = Decoder::with_unpack_size(42);
    let mut out = [0u8; 16];
    assert_eq!(dec.finish(&mut out), Err(Error::Unsupported));
}

// ─── poisoning + reset recovery ──────────────────────────────────────────

#[test]
fn poisoned_after_error_then_corrupt() {
    let mut dec = Decoder::with_unpack_size(42);
    let mut out = [0u8; 16];
    assert_eq!(dec.decode(&[0x00], &mut out), Err(Error::Unsupported));
    // Poisoned: further calls report Corrupt until reset.
    assert_eq!(dec.decode(&[0x00], &mut out), Err(Error::Corrupt));
    assert_eq!(dec.finish(&mut out), Err(Error::Corrupt));
}

#[test]
fn reset_restores_empty_member_semantics() {
    let mut dec = Decoder::with_unpack_size(0);
    let mut out = [0u8; 16];
    let (_p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(status, Status::StreamEnd);
    // After reset, the empty-member decoder is ready to "decode" again.
    dec.reset();
    let (p, status) = dec.decode(&[], &mut out).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::StreamEnd);
}

#[test]
fn reset_recovers_from_poison_to_payload_semantics() {
    let mut dec = Decoder::with_unpack_size(7);
    let mut out = [0u8; 16];
    assert_eq!(dec.decode(&[0x00], &mut out), Err(Error::Unsupported));
    assert_eq!(dec.decode(&[0x00], &mut out), Err(Error::Corrupt));
    dec.reset();
    // No longer Corrupt; back to the documented Unsupported payload gap.
    assert_eq!(dec.decode(&[0x00], &mut out), Err(Error::Unsupported));
}

// ─── factory by-name lookup ──────────────────────────────────────────────

#[cfg(feature = "factory")]
#[test]
fn factory_resolves_sit13() {
    use compcol::factory::{decoder_by_name, encoder_by_name, names};
    assert!(names().contains(&"sit13"));

    let mut enc = encoder_by_name("sit13").expect("encoder registered");
    let mut out = [0u8; 16];
    assert_eq!(enc.encode(b"x", &mut out), Err(Error::Unsupported));

    let mut dec = decoder_by_name("sit13").expect("decoder registered");
    // Default decoder (unspecified length) treats payload as Unsupported.
    assert_eq!(dec.decode(&[0x00], &mut out), Err(Error::Unsupported));
}
