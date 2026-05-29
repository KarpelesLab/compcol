//! Tests for `Encoder::flush(Sync | Full)`.
//!
//! Per-packet sync flushes are the load-bearing primitive for compressed
//! transports (SSH RFC 4253 §6.2 "zlib", HTTP/2 dynamic table updates, etc.).
//! These tests exercise the wire shape, decodability at every sync boundary,
//! history preservation across `Sync`, and history reset on `Full`.

#![cfg(feature = "deflate")]

use compcol::deflate::{Decoder, Encoder};
use compcol::{Decoder as _, Encoder as _, Error, Flush, Status};

// ─── helpers ─────────────────────────────────────────────────────────────

/// Drive `enc.encode` to drain `input` into `out`, looping until the
/// encoder reports `InputEmpty`. Mirrors the canonical loop pattern.
fn drive_encode<E: compcol::Encoder>(enc: &mut E, input: &[u8], out: &mut Vec<u8>) {
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::InputEmpty => break,
            Status::OutputFull => continue,
            Status::StreamEnd => panic!("encode returned StreamEnd"),
        }
    }
}

/// Drive `enc.flush(mode)` to completion, looping past partial-output
/// returns until the encoder reports `InputEmpty`. Asserts that flush
/// never returns `StreamEnd`.
fn drive_flush<E: compcol::Encoder>(enc: &mut E, mode: Flush, out: &mut Vec<u8>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (p, status) = enc.flush(&mut buf, mode).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        match status {
            Status::InputEmpty => break,
            Status::OutputFull => continue,
            Status::StreamEnd => panic!("flush returned StreamEnd"),
        }
    }
}

/// Drive `enc.finish()` until `StreamEnd`.
fn drive_finish<E: compcol::Encoder>(enc: &mut E, out: &mut Vec<u8>) {
    let mut buf = vec![0u8; 4096];
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        assert!(p.written > 0 || matches!(status, Status::OutputFull));
    }
}

/// Decode an entire deflate stream by repeated `decode` + `finish`.
fn decode_all(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    while consumed < encoded.len() {
        let (p, status) = dec.decode(&encoded[consumed..], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::StreamEnd => break,
            Status::InputEmpty => break,
            Status::OutputFull => continue,
        }
    }
    // Drain anything buffered internally.
    loop {
        let (p, _status) = dec.decode(&[], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if p.written == 0 {
            break;
        }
    }
    Ok(out)
}

/// Decode without requiring `finish` — used for partial streams that end
/// at a sync marker, where the deflate stream is not yet terminated.
fn decode_partial(encoded: &[u8]) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    while consumed < encoded.len() {
        let (p, status) = dec.decode(&encoded[consumed..], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::StreamEnd => return Ok(out),
            Status::InputEmpty => break,
            Status::OutputFull => continue,
        }
    }
    // Drain anything buffered internally — these are the literal bytes the
    // decoder produced from the just-decoded non-final block, before the
    // sync marker tail.
    loop {
        let (p, _status) = dec.decode(&[], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if p.written == 0 {
            break;
        }
    }
    Ok(out)
}

// ─── deflate ─────────────────────────────────────────────────────────────

/// Encode three chunks separated by `Sync` flushes, then verify each
/// intermediate prefix decodes to the expected partial content. Modelled
/// on the per-packet SSH zlib use case from RFC 4253 §6.2.
#[test]
fn deflate_three_chunks_with_sync_flushes() {
    let a: Vec<u8> = "AAAA".repeat(64).into_bytes(); // 256 bytes of 'A'
    let b: Vec<u8> = "BBBB".repeat(64).into_bytes();
    let c: Vec<u8> = "CCCC".repeat(64).into_bytes();

    let mut enc = Encoder::new();
    let mut wire = Vec::new();

    drive_encode(&mut enc, &a, &mut wire);
    drive_flush(&mut enc, Flush::Sync, &mut wire);
    let after_a = wire.len();

    drive_encode(&mut enc, &b, &mut wire);
    drive_flush(&mut enc, Flush::Sync, &mut wire);
    let after_b = wire.len();

    drive_encode(&mut enc, &c, &mut wire);
    drive_flush(&mut enc, Flush::Sync, &mut wire);
    drive_finish(&mut enc, &mut wire);

    // Full stream decodes to the concatenation.
    let full = decode_all(&wire).expect("decode full stream");
    let mut expected = Vec::new();
    expected.extend_from_slice(&a);
    expected.extend_from_slice(&b);
    expected.extend_from_slice(&c);
    assert_eq!(full, expected);

    // Prefix up through the first sync marker decodes to chunk A cleanly.
    let prefix_a = decode_partial(&wire[..after_a]).expect("decode prefix A");
    assert_eq!(prefix_a, a, "first-sync prefix should yield A");

    // Prefix up through the second sync marker decodes to A ++ B.
    let prefix_ab = decode_partial(&wire[..after_b]).expect("decode prefix AB");
    let mut ab = Vec::new();
    ab.extend_from_slice(&a);
    ab.extend_from_slice(&b);
    assert_eq!(prefix_ab, ab, "second-sync prefix should yield A++B");
}

/// After a `Sync` flush, encoding a long repeated pattern that exactly
/// reproduces a chunk of pre-flush data must back-reference the
/// pre-flush history, not re-emit literals. We verify by comparing the
/// compressed size against the raw-literal cost.
#[test]
fn deflate_history_preserved_across_sync() {
    // 16 KiB of unique-ish bytes — enough to give the matcher distinct
    // history to back-reference.
    let mut history = Vec::with_capacity(16 * 1024);
    for i in 0..(16 * 1024) {
        // A modular-arithmetic byte pattern. Repeating period 256 means
        // the second copy CAN back-reference the first.
        history.push((i & 0xff) as u8);
    }

    let mut enc = Encoder::new();
    let mut wire = Vec::new();

    drive_encode(&mut enc, &history, &mut wire);
    drive_flush(&mut enc, Flush::Sync, &mut wire);
    let after_sync = wire.len();

    // Now re-feed the SAME data. With history preserved, this must be
    // back-referenced as a long match (or many short matches), so the
    // post-flush portion of the wire is much smaller than a literal copy.
    drive_encode(&mut enc, &history, &mut wire);
    drive_flush(&mut enc, Flush::Sync, &mut wire);
    drive_finish(&mut enc, &mut wire);

    let post_flush_bytes = wire.len() - after_sync;
    // A literal-only encoding of 16 KiB would be ~16 KiB plus block headers.
    // With back-references the post-flush portion should compress to a tiny
    // fraction. Be generous to absorb encoder choices: must be < 10%.
    assert!(
        post_flush_bytes * 10 < history.len(),
        "post-flush portion {} bytes is too large vs history {} bytes — history not preserved across Sync",
        post_flush_bytes,
        history.len()
    );

    // Round-trip verification.
    let decoded = decode_all(&wire).expect("decode full stream");
    let mut expected = Vec::new();
    expected.extend_from_slice(&history);
    expected.extend_from_slice(&history);
    assert_eq!(decoded, expected);
}

/// `Full` flush resets the match finder, so after a `Full` flush, the
/// next block cannot back-reference data emitted before the flush. We
/// verify by sending a unique sentinel, then `Full`-flushing, then
/// sending the same sentinel again — the second copy must encode as
/// literals (post-flush byte count similar to first-copy byte count).
#[test]
fn deflate_full_flush_resets_history() {
    // Pseudo-random-ish but deterministic 4 KiB sentinel.
    let mut sentinel = Vec::with_capacity(4096);
    for i in 0..4096u32 {
        // Some non-trivial bytewise pattern.
        let v = ((i.wrapping_mul(2654435761)) >> 24) as u8;
        sentinel.push(v);
    }

    // Encoder 1: Full flush between two copies of the sentinel.
    let mut enc_full = Encoder::new();
    let mut wire_full = Vec::new();
    drive_encode(&mut enc_full, &sentinel, &mut wire_full);
    drive_flush(&mut enc_full, Flush::Full, &mut wire_full);
    let after_full_sync = wire_full.len();
    drive_encode(&mut enc_full, &sentinel, &mut wire_full);
    drive_flush(&mut enc_full, Flush::Sync, &mut wire_full);
    drive_finish(&mut enc_full, &mut wire_full);
    let post_full_bytes = wire_full.len() - after_full_sync;

    // Encoder 2: Sync flush (history preserved) between two copies — for
    // comparison. Post-flush portion should be much smaller than post-full.
    let mut enc_sync = Encoder::new();
    let mut wire_sync = Vec::new();
    drive_encode(&mut enc_sync, &sentinel, &mut wire_sync);
    drive_flush(&mut enc_sync, Flush::Sync, &mut wire_sync);
    let after_sync_sync = wire_sync.len();
    drive_encode(&mut enc_sync, &sentinel, &mut wire_sync);
    drive_flush(&mut enc_sync, Flush::Sync, &mut wire_sync);
    drive_finish(&mut enc_sync, &mut wire_sync);
    let post_sync_bytes = wire_sync.len() - after_sync_sync;

    // After Full flush, the second sentinel cannot back-reference — so
    // its encoded size should be at least 4× the Sync-flush case (which
    // typically compresses the second copy to <10% of its size).
    assert!(
        post_full_bytes > post_sync_bytes * 4,
        "post-Full ({} bytes) should be much larger than post-Sync ({} bytes) — Full flush did not reset history",
        post_full_bytes,
        post_sync_bytes
    );

    // Both wires must still round-trip cleanly.
    let mut expected = Vec::new();
    expected.extend_from_slice(&sentinel);
    expected.extend_from_slice(&sentinel);
    let decoded_full = decode_all(&wire_full).expect("decode Full wire");
    assert_eq!(decoded_full, expected);
    let decoded_sync = decode_all(&wire_sync).expect("decode Sync wire");
    assert_eq!(decoded_sync, expected);
}

/// Flush with an output buffer that's smaller than the marker: the
/// encoder must return `OutputFull`, the caller drains, and the marker
/// completes on subsequent calls. No second marker is emitted.
#[test]
fn deflate_flush_handles_tiny_output_buffer() {
    let mut enc = Encoder::new();
    let mut wire = Vec::new();
    drive_encode(&mut enc, b"hello world", &mut wire);

    // Use a 1-byte buffer to force OutputFull on every call.
    let mut buf = [0u8; 1];
    loop {
        let (p, status) = enc.flush(&mut buf, Flush::Sync).unwrap();
        wire.extend_from_slice(&buf[..p.written]);
        match status {
            Status::InputEmpty => break,
            Status::OutputFull => continue,
            Status::StreamEnd => panic!("flush returned StreamEnd"),
        }
    }
    drive_finish(&mut enc, &mut wire);

    let decoded = decode_all(&wire).expect("decode tiny-buffer wire");
    assert_eq!(decoded, b"hello world");
}

// ─── rle: default no-op ──────────────────────────────────────────────────

#[cfg(feature = "rle")]
#[test]
fn rle_flush_is_default_noop() {
    use compcol::rle;
    let mut enc = rle::Encoder::new();
    let mut buf = [0u8; 16];
    let (p, status) = enc.flush(&mut buf, Flush::Sync).unwrap();
    assert_eq!(p.consumed, 0);
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::InputEmpty));

    let (p, status) = enc.flush(&mut buf, Flush::Full).unwrap();
    assert_eq!(p.consumed, 0);
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::InputEmpty));
}

// ─── zlib: header + flush ────────────────────────────────────────────────

#[cfg(feature = "zlib")]
#[test]
fn zlib_flush_round_trips_without_trailer() {
    use compcol::zlib;
    let mut enc = zlib::Encoder::new();
    let mut wire = Vec::new();

    drive_encode(&mut enc, b"chunk one ", &mut wire);
    drive_flush(&mut enc, Flush::Sync, &mut wire);
    let after_first_flush = wire.len();
    drive_encode(&mut enc, b"chunk two ", &mut wire);
    drive_flush(&mut enc, Flush::Sync, &mut wire);
    drive_encode(&mut enc, b"chunk three", &mut wire);
    drive_finish(&mut enc, &mut wire);

    // Decode the full stream.
    let mut dec = zlib::Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    while consumed < wire.len() {
        let (p, status) = dec.decode(&wire[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if matches!(status, Status::InputEmpty) {
            break;
        }
    }
    assert_eq!(out, b"chunk one chunk two chunk three");

    // The wire after the first flush must NOT contain the 4-byte zlib
    // trailer (Adler-32). If it did, the decoder would have terminated
    // there and we'd be unable to continue feeding data. Sanity check:
    // the bytes between header and first flush boundary must not be a
    // complete zlib stream. A simple way: the prefix length must be
    // longer than 2 (header) + 4 (trailer) + 4 (sync marker) = 10
    // bytes, but more importantly, decoding the prefix on a fresh
    // decoder must NOT successfully `finish`.
    let mut probe = zlib::Decoder::new();
    let mut probe_out = vec![0u8; 4096];
    let mut probe_consumed = 0;
    while probe_consumed < after_first_flush {
        let (p, _status) = probe
            .decode(&wire[probe_consumed..after_first_flush], &mut probe_out)
            .unwrap();
        probe_consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    // We should never have hit a successful trailer validation here —
    // the deflate stream inside is still mid-flight.
    let finish_result = probe.finish(&mut probe_out);
    assert!(
        finish_result.is_err(),
        "zlib decoder finish on a sync-flushed prefix must error \
         (no trailer) — got Ok, meaning flush emitted a trailer"
    );
}

// ─── gzip: header + flush ────────────────────────────────────────────────

#[cfg(feature = "gzip")]
#[test]
fn gzip_flush_round_trips_without_trailer() {
    use compcol::gzip;
    let mut enc = gzip::Encoder::new();
    let mut wire = Vec::new();

    drive_encode(&mut enc, b"alpha ", &mut wire);
    drive_flush(&mut enc, Flush::Sync, &mut wire);
    let after_first_flush = wire.len();
    drive_encode(&mut enc, b"beta ", &mut wire);
    drive_flush(&mut enc, Flush::Sync, &mut wire);
    drive_encode(&mut enc, b"gamma", &mut wire);
    drive_finish(&mut enc, &mut wire);

    // Decode full.
    let mut dec = gzip::Decoder::new();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    while consumed < wire.len() {
        let (p, status) = dec.decode(&wire[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::StreamEnd | Status::InputEmpty) {
            break;
        }
    }
    assert_eq!(out, b"alpha beta gamma");

    // Confirm no trailer was emitted at the first flush boundary.
    let mut probe = gzip::Decoder::new();
    let mut probe_out = vec![0u8; 4096];
    let mut probe_consumed = 0;
    while probe_consumed < after_first_flush {
        let (p, _status) = probe
            .decode(&wire[probe_consumed..after_first_flush], &mut probe_out)
            .unwrap();
        probe_consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    let finish_result = probe.finish(&mut probe_out);
    assert!(
        finish_result.is_err(),
        "gzip decoder finish on a sync-flushed prefix must error \
         (no trailer) — got Ok, meaning flush emitted a trailer"
    );
}

// ─── empty-input flush ───────────────────────────────────────────────────

/// Flushing immediately after construction (no encoded data) must still
/// produce a valid sync marker that decodes to empty content and leaves
/// the stream usable.
#[test]
fn deflate_flush_with_no_pending_input() {
    let mut enc = Encoder::new();
    let mut wire = Vec::new();
    drive_flush(&mut enc, Flush::Sync, &mut wire);
    // The marker alone is some small number of bytes; nothing more.
    assert!(!wire.is_empty(), "flush should emit the sync marker");
    drive_encode(&mut enc, b"after", &mut wire);
    drive_finish(&mut enc, &mut wire);

    let decoded = decode_all(&wire).expect("decode empty-flush wire");
    assert_eq!(decoded, b"after");
}
