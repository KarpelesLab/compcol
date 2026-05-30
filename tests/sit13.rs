//! Integration tests for the StuffIt classic method-13 ("LZ+Huffman") codec.
//!
//! The primary validation walks a real classic `SIT!` archive, decodes every
//! method-13 fork with the out-of-band uncompressed length, and asserts the
//! decoded bytes match the per-fork CRC-16 stored in the container header
//! (reflected CRC-16, reversed polynomial `0xA001`, per spec §1.4).
//!
//! The bundled `sample.sit` is a compact, self-contained `SIT!` carved from
//! the staged `911_Utilities_2.0.sit` fixture: seven small method-13 forks
//! exercising every control-byte mode (predefined sets 1, 2, 4, 5 and the
//! dynamic / transmitted-codes path). The remaining tests cover the public
//! surface: metadata, the permanently-`Unsupported` encoder, empty-fork and
//! truncation handling, illegal control bytes, and factory lookup.

#![cfg(feature = "sit13")]

use compcol::sit13::{Decoder, DecoderConfig, Encoder, Sit13};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── helpers ──────────────────────────────────────────────────────────────

/// Reflected CRC-16 (reversed polynomial `0xA001`, init 0, no final XOR),
/// per the method-13 spec §1.4.
fn crc16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            if crc & 1 != 0 {
                crc = (crc >> 1) ^ 0xA001;
            } else {
                crc >>= 1;
            }
        }
    }
    crc
}

fn be16(d: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([d[o], d[o + 1]])
}
fn be32(d: &[u8], o: usize) -> usize {
    u32::from_be_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]) as usize
}

/// Decode a raw method-13 fork payload to `ulen` bytes via the streaming API.
fn decode_fork(payload: &[u8], ulen: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Sit13::decoder_with(DecoderConfig::with_len(ulen));
    let mut out = vec![0u8; ulen];
    let mut written = 0usize;
    let mut consumed = 0usize;
    loop {
        let (p, s) = dec.decode(&payload[consumed..], &mut out[written..])?;
        consumed += p.consumed;
        written += p.written;
        match s {
            Status::StreamEnd => break,
            Status::InputEmpty => break,
            Status::OutputFull => {
                if written >= out.len() {
                    break;
                }
            }
        }
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let (p, s) = dec.finish(&mut out[written..])?;
        written += p.written;
        if matches!(s, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    out.truncate(written);
    Ok(out)
}

/// A minimal classic `SIT!` walker, sufficient for the bundled fixture and the
/// staged `911_Utilities_2.0.sit`: 22-byte archive header, 112-byte big-endian
/// entry headers, folder start/end markers (`0x20`/`0x21`), resource fork
/// before data fork. Yields `(method_low_nibble, payload, uncompressed_len,
/// stored_crc)` for each fork.
fn walk_forks(data: &[u8]) -> Vec<(u8, &[u8], usize, u16)> {
    assert_eq!(&data[0..4], b"SIT!", "bad magic");
    assert_eq!(&data[10..14], b"rLau", "bad rLau tag");
    const HDR: usize = 112;
    let mut forks = Vec::new();
    let mut off = 22usize;
    while off + HDR <= data.len() {
        let rmeth = data[off];
        let dmeth = data[off + 1];
        // Folder start (0x20) / end (0x21) markers carry no fork data.
        if matches!(rmeth, 0x20 | 0x21) || matches!(dmeth, 0x20 | 0x21) {
            off += HDR;
            continue;
        }
        let rlen = be32(data, off + 84);
        let dlen = be32(data, off + 88);
        let rclen = be32(data, off + 92);
        let dclen = be32(data, off + 96);
        let rcrc = be16(data, off + 100);
        let dcrc = be16(data, off + 102);
        let data_off = off + HDR;
        let res = &data[data_off..data_off + rclen];
        let dat = &data[data_off + rclen..data_off + rclen + dclen];
        if rmeth & 0x0F == 13 {
            forks.push((rmeth & 0x0F, res, rlen, rcrc));
        }
        if dmeth & 0x0F == 13 {
            forks.push((dmeth & 0x0F, dat, dlen, dcrc));
        }
        off = data_off + rclen + dclen;
    }
    forks
}

// ─── primary validation: real SIT archive, CRC over decoded forks ─────────

#[test]
fn bundled_sit_all_method13_forks_pass_crc() {
    let data = include_bytes!("fixtures/sit13/sample.sit");
    let forks = walk_forks(data);
    assert_eq!(forks.len(), 7, "expected 7 method-13 forks in the fixture");

    let mut pass = 0usize;
    for (i, &(_method, payload, ulen, crc)) in forks.iter().enumerate() {
        let decoded = decode_fork(payload, ulen)
            .unwrap_or_else(|e| panic!("fork {i} failed to decode: {e:?}"));
        assert_eq!(decoded.len(), ulen, "fork {i} wrong length");
        let got = crc16(&decoded);
        assert_eq!(
            got, crc,
            "fork {i} CRC mismatch: got {got:#06x} want {crc:#06x}"
        );
        pass += 1;
    }
    assert_eq!(pass, 7);
}

// ─── algorithm metadata + factory shape ──────────────────────────────────

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
    let _ = Decoder::with_len(0);
    let _ = Decoder::with_len(1234);
    let _ = Decoder::default();
    let _ = Sit13::decoder_with(DecoderConfig::default());
    let _ = Sit13::decoder_with(DecoderConfig::with_len(99));
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

// ─── empty / truncated / illegal inputs ──────────────────────────────────

#[test]
fn empty_fork_decodes_to_empty() {
    let decoded = decode_fork(&[], 0).expect("empty fork should decode");
    assert!(decoded.is_empty());
}

#[test]
fn empty_member_decodes_to_empty_via_finish() {
    let mut dec = Decoder::with_len(0);
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
fn truncation_is_clean_error() {
    // High nibble 0 = dynamic; the decoder then needs the transmitted
    // code-length lists, which are absent.
    let err = decode_fork(&[0x00], 64).expect_err("truncated stream must error");
    assert!(
        matches!(err, Error::UnexpectedEnd | Error::Corrupt),
        "unexpected error variant: {err:?}"
    );
}

#[test]
fn illegal_control_byte_is_corrupt() {
    for ctrl in [0x60u8, 0x70, 0xF0, 0xFF] {
        let err = decode_fork(&[ctrl, 0, 0, 0], 16).expect_err("illegal control byte must error");
        assert_eq!(err, Error::Corrupt, "control {ctrl:#x}");
    }
}

// ─── poisoning + reset recovery ──────────────────────────────────────────

#[test]
fn poisoned_after_error_then_corrupt() {
    let mut dec = Decoder::with_len(16);
    let mut out = [0u8; 16];
    // Illegal control byte → error, then poisoned.
    let _ = dec.decode(&[0xF0, 0, 0, 0], &mut out);
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn reset_restores_empty_member_semantics() {
    let mut dec = Decoder::with_len(0);
    let mut out = [0u8; 16];
    let (_p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(status, Status::StreamEnd);
    dec.reset();
    let (p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::StreamEnd);
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

    let _dec = decoder_by_name("sit13").expect("decoder registered");
}
