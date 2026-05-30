//! Integration tests for the StuffIt 5 Arsenic (method 15) decoder.
//!
//! A minimal StuffIt 5 container walker (per FORMAT-SPEC §1, adapted to the
//! real on-disk layout of the staged fixtures) locates every method-15 fork
//! and feeds its compressed range to the Arsenic decoder. Each decoded fork
//! is validated by (a) the in-stream CRC-32 trailer (verified inside the
//! decoder — a mismatch returns `Corrupt`), and (b) the decoded length
//! matching the container's uncompressed-size field.

#![cfg(feature = "arsenic")]

use compcol::arsenic::Arsenic;
use compcol::{Algorithm, Decoder, Error, Status};

/// The smallest staged fixture, bundled into the repo.
const GALAX_SIT: &[u8] = include_bytes!("fixtures/arsenic/Galax.SIT");

/// A method-15 fork located by the container walker.
struct Fork {
    /// Compressed payload (the raw method-15 fork bytes).
    data: std::ops::Range<usize>,
    /// Declared uncompressed size.
    uncompressed: usize,
    /// True for the data fork, false for the resource fork.
    is_data: bool,
}

/// Walk a StuffIt 5 archive and return every method-15 (Arsenic) fork.
///
/// Layout discovered from the real fixtures:
/// - Archive begins with `"StuffIt"` + one terminator byte (`'!'`/`' '`/`'?'`).
/// - Entries are tagged with magic `0xA5A5A5A5`. The common header is 48
///   bytes: `+6` u16 header size (= 48 + name length), `+9` flags (bit
///   `0x40` = directory), `+31` name length, name at `+48`.
/// - The **data fork** descriptor lives in the common header: uncompressed
///   size at `+34`, compressed size at `+38`, method byte at `+46`.
/// - The **resource fork** descriptor is the 50-byte extended record at
///   `forkbase = entrystart + header_size`: uncompressed size at
///   `forkbase+36`, compressed size at `forkbase+40`, method byte at
///   `forkbase+48`.
/// - Resource-fork data begins at `forkbase + 50` (length = rsrc compressed),
///   immediately followed by the data-fork data (length = data compressed).
///
/// The walker scans for every `0xA5A5A5A5` magic (robust to the exact
/// sibling/child threading) and parses each non-directory entry.
fn walk_stuffit5(d: &[u8]) -> Vec<Fork> {
    assert!(d.len() >= 8, "archive too small");
    assert_eq!(&d[..7], b"StuffIt", "bad archive signature");
    assert!(
        matches!(d[7], b'!' | b' ' | b'?'),
        "bad archive signature terminator: {:#x}",
        d[7]
    );

    let be32 = |o: usize| u32::from_be_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]]) as usize;

    let mut forks = Vec::new();
    let mut i = 0usize;
    while i + 48 <= d.len() {
        if d[i..i + 4] != [0xA5, 0xA5, 0xA5, 0xA5] {
            i += 1;
            continue;
        }
        let header_size = u16::from_be_bytes([d[i + 6], d[i + 7]]) as usize;
        let is_dir = d[i + 9] & 0x40 != 0;
        if is_dir || header_size < 48 || i + header_size > d.len() {
            i += 4;
            continue;
        }
        let forkbase = i + header_size;

        // Data-fork descriptor (common header).
        let data_unc = be32(i + 34);
        let data_comp = be32(i + 38);
        let data_method = d[i + 46];

        // Resource-fork descriptor (extended record).
        let (mut rsrc_unc, mut rsrc_comp, mut rsrc_method) = (0usize, 0usize, 0u8);
        if forkbase + 50 <= d.len() {
            rsrc_unc = be32(forkbase + 36);
            rsrc_comp = be32(forkbase + 40);
            rsrc_method = d[forkbase + 48];
        }
        let rsrc_off = forkbase + 50;
        let data_off = rsrc_off + rsrc_comp;

        if rsrc_method == 15 && rsrc_comp > 0 && rsrc_off + rsrc_comp <= d.len() {
            forks.push(Fork {
                data: rsrc_off..rsrc_off + rsrc_comp,
                uncompressed: rsrc_unc,
                is_data: false,
            });
        }
        if data_method == 15 && data_comp > 0 && data_off + data_comp <= d.len() {
            forks.push(Fork {
                data: data_off..data_off + data_comp,
                uncompressed: data_unc,
                is_data: true,
            });
        }
        i += 4;
    }
    forks
}

/// Stream `input` through the Arsenic decoder in `in_chunk`-byte input
/// chunks and `out_chunk`-byte output chunks, returning the decoded bytes.
fn decode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Arsenic::decoder();
    let mut out = Vec::new();
    let mut obuf = vec![0u8; out_chunk.max(1)];
    let mut pos = 0usize;

    // Feed input in chunks; drain output fully on each call.
    loop {
        let end = (pos + in_chunk.max(1)).min(input.len());
        let chunk = &input[pos..end];
        let mut consumed_total = 0usize;
        loop {
            let (p, status) = dec.decode(&chunk[consumed_total..], &mut obuf)?;
            out.extend_from_slice(&obuf[..p.written]);
            consumed_total += p.consumed;
            match status {
                Status::StreamEnd => return Ok(out),
                Status::OutputFull => continue,
                Status::InputEmpty => break,
            }
        }
        pos = end;
        if pos >= input.len() {
            break;
        }
    }
    // Drain the tail via finish().
    loop {
        let (p, status) = dec.finish(&mut obuf)?;
        out.extend_from_slice(&obuf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    Ok(out)
}

#[test]
fn galax_fixture_decodes_and_verifies() {
    let forks = walk_stuffit5(GALAX_SIT);
    assert_eq!(forks.len(), 1, "expected exactly one method-15 fork");
    let fork = &forks[0];
    // Galax stores its Arsenic payload in the resource fork.
    assert!(!fork.is_data, "Galax's only fork is a resource fork");
    let compressed = &GALAX_SIT[fork.data.clone()];

    // One-shot decode (in-stream CRC verified inside the decoder).
    let out = decode_chunked(compressed, compressed.len(), 1 << 16)
        .expect("Galax fork should decode and pass its in-stream CRC");
    assert_eq!(
        out.len(),
        fork.uncompressed,
        "decoded length must equal the container's uncompressed size"
    );
}

#[test]
fn galax_fixture_decodes_under_byte_chunking() {
    let forks = walk_stuffit5(GALAX_SIT);
    let fork = &forks[0];
    let compressed = &GALAX_SIT[fork.data.clone()];

    // 1-byte input chunks, 1-byte output chunks: exercises the resumable
    // state machine under the most adversarial chunking.
    let out = decode_chunked(compressed, 1, 1).expect("byte-chunked decode should match one-shot");
    assert_eq!(out.len(), fork.uncompressed);

    let one_shot = decode_chunked(compressed, compressed.len(), 1 << 16).unwrap();
    assert_eq!(out, one_shot, "chunking must not change the output");
}

#[test]
fn empty_input_needs_more_then_errors_on_finish() {
    // No input at all: decode returns InputEmpty (not done); finish on a
    // never-terminated stream is UnexpectedEnd.
    let mut dec = Arsenic::decoder();
    let mut obuf = [0u8; 16];
    let (p, status) = dec.decode(&[], &mut obuf).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::InputEmpty);
    let err = dec.finish(&mut obuf).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn truncated_stream_is_clean_error() {
    // Feed only the first few bytes of a real fork, then finish: the stream
    // never reaches its in-band terminator, so finish must report
    // UnexpectedEnd rather than loop or panic.
    let forks = walk_stuffit5(GALAX_SIT);
    let compressed = &GALAX_SIT[forks[0].data.clone()];
    let truncated = &compressed[..16];

    let mut dec = Arsenic::decoder();
    let mut obuf = [0u8; 256];
    // Decode may make no progress (need more input).
    let _ = dec.decode(truncated, &mut obuf);
    let err = dec.finish(&mut obuf).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn bad_signature_is_corrupt() {
    // A fully-present but bogus stream whose decoded "As" tag is wrong must
    // be rejected as Corrupt (not UnexpectedEnd). Feed plenty of bytes so the
    // decoder does not bail on underflow before the signature check.
    let bogus = vec![0xFFu8; 512];
    let mut dec = Arsenic::decoder();
    let mut obuf = [0u8; 256];
    // It either errors on decode or on finish; in both cases it must be
    // Corrupt, never a panic.
    let r1 = dec.decode(&bogus, &mut obuf);
    let err = match r1 {
        Err(e) => e,
        Ok(_) => dec.finish(&mut obuf).unwrap_err(),
    };
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn encoder_is_unsupported() {
    use compcol::Encoder;
    let mut enc = Arsenic::encoder();
    let mut obuf = [0u8; 16];
    assert_eq!(
        enc.encode(b"hi", &mut obuf).unwrap_err(),
        Error::Unsupported
    );
}

#[test]
fn factory_registration() {
    #[cfg(feature = "factory")]
    {
        assert!(compcol::factory::decoder_by_name("arsenic").is_some());
        assert!(compcol::factory::names().contains(&"arsenic"));
        assert_eq!(compcol::factory::extension("arsenic"), Some("arsenic"));
    }
}
