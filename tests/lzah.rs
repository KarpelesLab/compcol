//! StuffIt classic method 5 ("LZAH") decoder tests.
//!
//! The interop tests validate against *real* classic `SIT!` archives: a
//! minimal container walker extracts every method-5 fork, the decoder
//! reconstructs it from the raw payload with the out-of-band uncompressed
//! length, and the recomputed CRC-16 is checked against the value stored in
//! the archive entry header. A passing CRC over genuine StuffIt data proves
//! bit-exact interoperability.
//!
//! One small fixture (`tests/fixtures/lzah/convert-archive-fix.sit`, the
//! ~2.8 KB "Dlx 2.0 Convert Archive Fix.sit" sample, 3 method-5 forks) is
//! bundled so CI is self-contained. During local development the test also
//! walks the larger staged fixtures under `/tmp/cleanroom-stage/lzah` when
//! present, for broader coverage.

#![cfg(feature = "lzah")]

use compcol::lzah::{DecoderConfig, Lzah};
use compcol::{Algorithm, Decoder, Status};

// ─── helpers ───────────────────────────────────────────────────────────────

/// Decode a raw method-5 payload to `expected_len` bytes via the streaming
/// decoder.
fn decode(payload: &[u8], expected_len: usize) -> Result<Vec<u8>, compcol::Error> {
    let mut dec = Lzah::decoder_with(DecoderConfig::with_len(expected_len));
    let mut out = Vec::new();
    let mut buf = [0u8; 8192];

    // Feed the whole payload.
    let mut consumed = 0;
    while consumed < payload.len() {
        let (p, _st) = dec.decode(&payload[consumed..], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    // Drain.
    loop {
        let (p, st) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(st, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    Ok(out)
}

/// CRC-16 with reflected polynomial 0xA001, init 0, no final xor, LSB-first
/// byte processing (spec section 3.4).
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

fn be_u16(b: &[u8], off: usize) -> u16 {
    u16::from_be_bytes([b[off], b[off + 1]])
}
fn be_u32(b: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

/// A single fork extracted from an archive entry.
struct Fork {
    method: u8,
    uncompressed_len: usize,
    payload_off: usize,
    compressed_len: usize,
    stored_crc: u16,
}

/// Walk a classic `SIT!` archive and return every fork (resource + data) in
/// file order. Returns `None` if the magic doesn't match.
fn walk_sit(arc: &[u8]) -> Option<Vec<Fork>> {
    if arc.len() < 22 {
        return None;
    }
    // Magic: bytes[0..4] == "SIT!" and bytes[10..14] == "rLau".
    if &arc[0..4] != b"SIT!" || &arc[10..14] != b"rLau" {
        return None;
    }

    let mut forks = Vec::new();
    let mut pos = 22usize; // archive header size

    while pos + 112 <= arc.len() {
        let hdr = &arc[pos..pos + 112];
        let res_method = hdr[0];
        let data_method = hdr[1];

        // Folder markers (after masking flags) carry no payload.
        let res_low = res_method & 0x0f;
        let data_low = data_method & 0x0f;
        if res_low == 0x00 && (res_method == 0x20 || res_method == 0x21) {
            // Folder start/end marker — no payload, advance one header.
            pos += 112;
            continue;
        }

        let res_uncomp = be_u32(hdr, 84) as usize;
        let data_uncomp = be_u32(hdr, 88) as usize;
        let res_comp = be_u32(hdr, 92) as usize;
        let data_comp = be_u32(hdr, 96) as usize;
        let res_crc = be_u16(hdr, 100);
        let data_crc = be_u16(hdr, 102);

        let mut p = pos + 112;
        // Resource fork first, then data fork.
        forks.push(Fork {
            method: res_low,
            uncompressed_len: res_uncomp,
            payload_off: p,
            compressed_len: res_comp,
            stored_crc: res_crc,
        });
        p += res_comp;
        forks.push(Fork {
            method: data_low,
            uncompressed_len: data_uncomp,
            payload_off: p,
            compressed_len: data_comp,
            stored_crc: data_crc,
        });
        p += data_comp;

        pos = p;
    }

    Some(forks)
}

/// Decode and CRC-validate every method-5 fork in `arc`; returns the number
/// of method-5 forks that passed.
fn validate_archive(arc: &[u8]) -> usize {
    let forks = walk_sit(arc).expect("recognised SIT! archive");
    let mut passed = 0;
    for f in &forks {
        if f.method != 5 {
            continue;
        }
        let end = f.payload_off + f.compressed_len;
        assert!(end <= arc.len(), "fork payload within archive bounds");
        let payload = &arc[f.payload_off..end];
        let decoded = decode(payload, f.uncompressed_len)
            .unwrap_or_else(|e| panic!("method-5 decode failed: {e:?}"));
        assert_eq!(
            decoded.len(),
            f.uncompressed_len,
            "decoded length matches header"
        );
        let crc = crc16(&decoded);
        assert_eq!(
            crc, f.stored_crc,
            "CRC-16 mismatch (got {:#06x}, want {:#06x})",
            crc, f.stored_crc
        );
        passed += 1;
    }
    passed
}

// ─── interop: bundled fixture ───────────────────────────────────────────────

static CONVERT_ARCHIVE_FIX: &[u8] = include_bytes!("fixtures/lzah/convert-archive-fix.sit");

#[test]
fn interop_bundled_fixture_crc() {
    let passed = validate_archive(CONVERT_ARCHIVE_FIX);
    // The fixture contains 3 method-5 forks.
    assert_eq!(passed, 3, "expected 3 method-5 forks to CRC-validate");
}

// ─── interop: full staged fixture set (dev only) ───────────────────────────

#[test]
fn interop_staged_fixtures_crc() {
    use std::path::Path;
    let base = Path::new("/tmp/cleanroom-stage/lzah/FIXTURES");
    if !base.exists() {
        // Staged fixtures not present (CI): the bundled fixture test covers
        // interop on its own.
        return;
    }
    let mut total_forks = 0usize;
    let mut total_archives = 0usize;
    for entry in std::fs::read_dir(base).unwrap() {
        let dir = entry.unwrap().path();
        let input = dir.join("input");
        if !input.is_dir() {
            continue;
        }
        for f in std::fs::read_dir(&input).unwrap() {
            let p = f.unwrap().path();
            if p.extension().and_then(|e| e.to_str()) != Some("sit") {
                continue;
            }
            let arc = std::fs::read(&p).unwrap();
            if walk_sit(&arc).is_some() {
                let n = validate_archive(&arc);
                total_forks += n;
                total_archives += 1;
            }
        }
    }
    eprintln!(
        "lzah staged fixtures: {} method-5 forks across {} archives validated",
        total_forks, total_archives
    );
    assert!(
        total_forks > 0,
        "expected at least one staged method-5 fork"
    );
}

// ─── unit tests ─────────────────────────────────────────────────────────────

#[test]
fn empty_fork_is_empty() {
    // expected_len 0 → no output, no symbols consumed.
    let out = decode(&[], 0).unwrap();
    assert!(out.is_empty());
    // Non-empty payload but zero declared length still yields empty.
    let out = decode(&[0xff, 0x00, 0xaa], 0).unwrap();
    assert!(out.is_empty());
}

#[test]
fn none_length_on_nonempty_is_unsupported() {
    let mut dec = Lzah::decoder(); // default config: expected_len = None
    let mut buf = [0u8; 64];
    // Feed a non-empty payload, then finish — must reject.
    let (_p, _st) = dec.decode(&[0x12, 0x34, 0x56], &mut buf).unwrap();
    let err = dec.finish(&mut buf).unwrap_err();
    assert_eq!(err, compcol::Error::Unsupported);
}

#[test]
fn none_length_on_empty_is_ok() {
    let mut dec = Lzah::decoder();
    let mut buf = [0u8; 64];
    let (p, st) = dec.finish(&mut buf).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(st, Status::StreamEnd);
}

#[test]
fn truncation_is_clean_error() {
    // Take a real method-5 fork and feed only its first few bytes with the
    // full declared length: the decoder must error, not panic.
    let forks = walk_sit(CONVERT_ARCHIVE_FIX).unwrap();
    let f = forks.iter().find(|f| f.method == 5).unwrap();
    let full = &CONVERT_ARCHIVE_FIX[f.payload_off..f.payload_off + f.compressed_len];
    let truncated = &full[..full.len() / 4];
    let err = decode(truncated, f.uncompressed_len).unwrap_err();
    assert!(matches!(
        err,
        compcol::Error::UnexpectedEnd | compcol::Error::Corrupt
    ));
}
