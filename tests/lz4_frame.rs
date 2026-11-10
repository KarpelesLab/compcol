//! Streaming round-trip + interop tests for the canonical LZ4 Frame
//! format (`compcol::lz4::frame`).

#![cfg(feature = "lz4")]

use compcol::lz4::frame::{BlockMaxSize, Decoder, Encoder, EncoderConfig, LZ4Frame};
use compcol::{Algorithm, Decoder as _, Encoder as _, Status};

// ─── Helpers ──────────────────────────────────────────────────────────────

fn encode_with_cfg_chunked(
    cfg: EncoderConfig,
    input: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Vec<u8> {
    let mut enc = Encoder::with_config(cfg);
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = enc.encode(&chunk[consumed..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }

    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("encoder finish stalled");
                }
            }
        }
    }

    encoded
}

fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    encode_with_cfg_chunked(EncoderConfig::default(), input, in_chunk, out_chunk)
}

fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }

    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("decoder finish stalled");
                }
            }
        }
    }

    decoded
}

fn round_trip_with(cfg: EncoderConfig, input: &[u8]) {
    let big = input.len().saturating_mul(2).max(4096);
    let encoded = encode_with_cfg_chunked(cfg, input, big, big);
    let decoded = decode_chunked(&encoded, big, big);
    assert_eq!(decoded.len(), input.len(), "round-trip length mismatch");
    assert_eq!(decoded, input, "round-trip content mismatch");
}

fn round_trip(input: &[u8]) {
    round_trip_with(EncoderConfig::default(), input);
}

// ─── Basic round-trip ────────────────────────────────────────────────────

#[test]
fn name_is_lz4_frame() {
    assert_eq!(<LZ4Frame as Algorithm>::NAME, "lz4-frame");
}

#[test]
fn empty_input() {
    round_trip(&[]);
}

#[test]
fn single_byte() {
    round_trip(&[0x42]);
}

#[test]
fn hello_world() {
    round_trip(b"hello world");
}

#[test]
fn round_trip_64kib() {
    let mut v = Vec::with_capacity(64 * 1024);
    let sentence = b"the quick brown fox jumps over the lazy dog. ";
    while v.len() < 64 * 1024 {
        v.extend_from_slice(sentence);
    }
    v.truncate(64 * 1024);
    round_trip(&v);
}

#[test]
fn round_trip_1mib_pseudo_random() {
    // Tiny LCG, fixed seed; keeps the test dependency-free.
    let mut state: u32 = 0xC0FFEEu32;
    let mut v = Vec::with_capacity(1024 * 1024);
    for _ in 0..(1024 * 1024) {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.push((state >> 16) as u8);
    }
    round_trip(&v);
}

#[test]
fn round_trip_mixed_corpus() {
    // Mix of random + highly compressible.
    let mut v = Vec::with_capacity(300 * 1024);
    let mut state: u32 = 0xDEAD_BEEF;
    while v.len() < 300 * 1024 {
        for _ in 0..1024 {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            v.push((state >> 16) as u8);
        }
        let sentence = b"the quick brown fox jumps over the lazy dog. ";
        let mut remaining = 1024usize;
        while remaining > 0 {
            let take = sentence.len().min(remaining);
            v.extend_from_slice(&sentence[..take]);
            remaining -= take;
        }
    }
    round_trip(&v);
}

#[test]
fn chunked_one_byte_at_a_time() {
    let input: Vec<u8> = (0..512u32).map(|i| (i % 7) as u8).collect();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

// ─── Hard-coded `lz4 -c` fixture ─────────────────────────────────────────

#[test]
fn decode_known_fixture() {
    // Produced offline with `printf 'hello' | lz4 -c | xxd -i`. Encodes
    // a 5-byte payload with the `lz4` CLI's default options:
    // magic 04 22 4d 18, FLG 0x64 (B.Indep + C.Checksum + version=01),
    // BD 0x40 (block max = 64 KiB), HC = 0xa7. One block with the
    // uncompressed bit set carrying "hello", then a zero EndMark and
    // the content xxHash32.
    let bytes: [u8; 24] = [
        0x04, 0x22, 0x4d, 0x18, 0x64, 0x40, 0xa7, 0x05, 0x00, 0x00, 0x80, 0x68, 0x65, 0x6c, 0x6c,
        0x6f, 0x00, 0x00, 0x00, 0x00, 0xf9, 0x77, 0x00, 0xfb,
    ];
    let decoded = decode_chunked(&bytes, 4096, 4096);
    assert_eq!(decoded, b"hello");
}

// ─── Block-size matrix ───────────────────────────────────────────────────

#[test]
fn block_size_64kb() {
    let cfg = EncoderConfig {
        block_max_size: BlockMaxSize::Max64KB,
        ..Default::default()
    };
    let mut v = Vec::with_capacity(200 * 1024);
    let s = b"the quick brown fox. ";
    while v.len() < 200 * 1024 {
        v.extend_from_slice(s);
    }
    round_trip_with(cfg, &v);
}

#[test]
fn block_size_256kb() {
    let cfg = EncoderConfig {
        block_max_size: BlockMaxSize::Max256KB,
        ..Default::default()
    };
    let mut v = Vec::with_capacity(600 * 1024);
    let s = b"the quick brown fox. ";
    while v.len() < 600 * 1024 {
        v.extend_from_slice(s);
    }
    round_trip_with(cfg, &v);
}

#[test]
fn block_size_1mb() {
    let cfg = EncoderConfig {
        block_max_size: BlockMaxSize::Max1MB,
        ..Default::default()
    };
    // Three blocks at 1 MiB each.
    let mut v = Vec::with_capacity(3 * 1024 * 1024);
    let mut state: u32 = 0xABCD_1234;
    while v.len() < 3 * 1024 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        v.push((state >> 16) as u8);
    }
    round_trip_with(cfg, &v);
}

#[test]
fn block_size_4mb() {
    let cfg = EncoderConfig {
        block_max_size: BlockMaxSize::Max4MB,
        ..Default::default()
    };
    // Just over 4 MiB so we test the second-block path with the
    // largest block size.
    let mut v = Vec::with_capacity(5 * 1024 * 1024);
    let mut state: u32 = 0x1357_9BDF;
    while v.len() < 5 * 1024 * 1024 {
        state = state.wrapping_mul(22_695_477).wrapping_add(1);
        v.push((state >> 16) as u8);
    }
    round_trip_with(cfg, &v);
}

// ─── Checksums ───────────────────────────────────────────────────────────

#[test]
fn content_checksum_round_trip() {
    let cfg = EncoderConfig {
        content_checksum: true,
        ..Default::default()
    };
    round_trip_with(cfg, b"the quick brown fox");
}

#[test]
fn content_checksum_detects_corruption() {
    let cfg = EncoderConfig {
        content_checksum: true,
        ..Default::default()
    };
    let payload = b"the quick brown fox jumps over the lazy dog";
    let mut encoded = encode_with_cfg_chunked(cfg, payload, 4096, 4096);
    // Flip a byte in the middle (avoid the 7-byte header/HC region and
    // the 4-byte EndMark + 4-byte trailing checksum).
    let mid = encoded.len() / 2;
    encoded[mid] ^= 0x01;

    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    let result = loop {
        let r = dec.decode(&encoded[consumed..], &mut buf);
        match r {
            Ok((p, status)) => {
                consumed += p.consumed;
                match status {
                    Status::StreamEnd => break Ok(()),
                    Status::InputEmpty if consumed >= encoded.len() => break Ok(()),
                    _ => {}
                }
                if p.consumed == 0 && p.written == 0 {
                    break Ok(());
                }
            }
            Err(e) => break Err(e),
        }
    };
    let err = match result {
        Ok(()) => {
            // If decode itself succeeded, finish must catch it.
            match dec.finish(&mut buf) {
                Ok(_) => panic!("expected ChecksumMismatch or Corrupt, got success"),
                Err(e) => e,
            }
        }
        Err(e) => e,
    };
    // The flipped byte could land in either the compressed payload (most
    // likely a Corrupt from the block decoder) or in the content
    // checksum bytes themselves (giving ChecksumMismatch). Either way
    // the decoder must reject the stream.
    assert!(
        matches!(
            err,
            compcol::Error::ChecksumMismatch
                | compcol::Error::Corrupt
                | compcol::Error::InvalidDistance
                | compcol::Error::UnexpectedEnd
        ),
        "got unexpected error: {err:?}"
    );
}

#[test]
fn block_checksum_round_trip() {
    let cfg = EncoderConfig {
        block_checksum: true,
        content_checksum: false,
        ..Default::default()
    };
    round_trip_with(cfg, b"the quick brown fox");

    // A longer, multi-block payload exercises block-checksum reads at
    // multiple positions.
    let mut v = Vec::with_capacity(200 * 1024);
    let s = b"the quick brown fox jumps over the lazy dog. ";
    while v.len() < 200 * 1024 {
        v.extend_from_slice(s);
    }
    round_trip_with(cfg, &v);
}

#[test]
fn block_checksum_detects_corruption() {
    let cfg = EncoderConfig {
        block_checksum: true,
        content_checksum: false,
        ..Default::default()
    };
    let payload = b"the quick brown fox jumps over the lazy dog";
    let mut encoded = encode_with_cfg_chunked(cfg, payload, 4096, 4096);
    // The header is 7 bytes. The 4-byte block size word follows, then
    // the block bytes. Flip a payload byte (offset 12 — clearly inside
    // the block data) so the block checksum will reject.
    encoded[12] ^= 0x80;

    let mut dec = Decoder::new();
    let mut buf = vec![0u8; 4096];
    let mut consumed = 0;
    let err = loop {
        match dec.decode(&encoded[consumed..], &mut buf) {
            Ok((p, status)) => {
                consumed += p.consumed;
                if matches!(status, Status::StreamEnd) {
                    match dec.finish(&mut buf) {
                        Ok(_) => panic!("expected ChecksumMismatch, got success"),
                        Err(e) => break e,
                    }
                }
                if p.consumed == 0 && p.written == 0 {
                    match dec.finish(&mut buf) {
                        Ok(_) => panic!("expected ChecksumMismatch, got success"),
                        Err(e) => break e,
                    }
                }
            }
            Err(e) => break e,
        }
    };
    assert!(
        matches!(
            err,
            compcol::Error::ChecksumMismatch
                | compcol::Error::Corrupt
                | compcol::Error::InvalidDistance
        ),
        "got unexpected error: {err:?}"
    );
}

// ─── Hand-built frames ───────────────────────────────────────────────────

/// Decode `encoded` in one shot, returning the output or the first error.
fn try_decode(encoded: &[u8]) -> Result<Vec<u8>, compcol::Error> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; 64 * 1024];
    let mut consumed = 0;
    loop {
        let (p, status) = dec.decode(&encoded[consumed..], &mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::StreamEnd => break,
            Status::InputEmpty if consumed == encoded.len() => break,
            _ => {}
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        if status == Status::StreamEnd {
            return Ok(decoded);
        }
        assert!(p.written > 0, "decoder finish stalled");
    }
}

/// Magic + `descriptor` (FLG, BD, optional fields) + the matching header
/// checksum byte. The HC is found by asking the decoder, which answers
/// `BadHeader` for every wrong value, so the tests need no xxHash of
/// their own.
fn frame_header(descriptor: &[u8]) -> Vec<u8> {
    let mut header = vec![0x04, 0x22, 0x4D, 0x18];
    header.extend_from_slice(descriptor);
    header.push(0);
    for hc in 0..=255u8 {
        *header.last_mut().unwrap() = hc;
        let mut dec = Decoder::new();
        if dec.decode(&header, &mut [0u8; 16]).is_ok() {
            return header;
        }
    }
    panic!("no header checksum accepted for {descriptor:02X?}");
}

/// A frame declaring `content_size` whose body is the given uncompressed
/// blocks followed by the EndMark.
fn frame_with_content_size(content_size: u64, blocks: &[&[u8]]) -> Vec<u8> {
    // FLG = version 01 | block independence | content size; BD = 64 KiB.
    let mut descriptor = vec![0x68, 0x40];
    descriptor.extend_from_slice(&content_size.to_le_bytes());
    let mut frame = frame_header(&descriptor);
    for block in blocks {
        frame.extend_from_slice(&(block.len() as u32 | 0x8000_0000).to_le_bytes());
        frame.extend_from_slice(block);
    }
    frame.extend_from_slice(&[0, 0, 0, 0]);
    frame
}

#[test]
fn content_size_matching_is_accepted() {
    let frame = frame_with_content_size(5, &[b"hello"]);
    assert_eq!(try_decode(&frame).unwrap(), b"hello");
    let frame = frame_with_content_size(10, &[b"hello", b"world"]);
    assert_eq!(try_decode(&frame).unwrap(), b"helloworld");
    let frame = frame_with_content_size(0, &[]);
    assert_eq!(try_decode(&frame).unwrap(), b"");
}

#[test]
fn content_size_larger_than_content_is_rejected() {
    // The audit's reproducer: Content_Size says 999, the frame holds 5
    // bytes. Reference `lz4 -d` reports ERROR_frameSize_wrong.
    let frame = [
        0x04, 0x22, 0x4D, 0x18, 0x68, 0x40, 0xE7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15,
        0x05, 0x00, 0x00, 0x80, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(frame.to_vec(), frame_with_content_size(999, &[b"hello"]));
    assert_eq!(try_decode(&frame), Err(compcol::Error::Corrupt));
}

#[test]
fn content_size_smaller_than_content_is_rejected() {
    let frame = frame_with_content_size(3, &[b"hello"]);
    assert_eq!(try_decode(&frame), Err(compcol::Error::Corrupt));
    // The overrun is caught at the block that crosses the declared size,
    // before a later block is even looked at.
    let mut frame = frame_with_content_size(7, &[b"hello", b"world"]);
    frame.truncate(frame.len() - 4); // no EndMark needed to notice
    assert_eq!(try_decode(&frame), Err(compcol::Error::Corrupt));
}

/// Append an uncompressed block to a hand-built frame.
fn push_raw_block(frame: &mut Vec<u8>, data: &[u8]) {
    frame.extend_from_slice(&(data.len() as u32 | 0x8000_0000).to_le_bytes());
    frame.extend_from_slice(data);
}

/// Append a compressed block holding one 4-byte match at `offset` followed
/// by the single literal `tail`.
fn push_match_block(frame: &mut Vec<u8>, offset: u16, tail: u8) {
    let [lo, hi] = offset.to_le_bytes();
    frame.extend_from_slice(&5u32.to_le_bytes());
    frame.extend_from_slice(&[0x00, lo, hi, 0x10, tail]);
}

#[test]
fn linked_frame_of_tiny_blocks() {
    // A linked-mode frame (FLG = 0x40) made of one 64 KiB block followed by
    // a long run of 1-byte blocks. The decoder used to slide its 64 KiB
    // history window with a full memmove for every one of them (~30x
    // slower than the same frame in independent mode); the window is now
    // trimmed in amortised O(1) per byte. No timing assertion here — this
    // pins the output of that path.
    const TINY: usize = 100_000;
    let mut expected: Vec<u8> = (0..64 * 1024u32)
        .map(|i| (i * 7 + (i >> 8)) as u8)
        .collect();
    let mut frame = frame_header(&[0x40, 0x40]);
    push_raw_block(&mut frame, &expected);
    for i in 0..TINY {
        let b = (i % 251) as u8;
        frame.extend_from_slice(&[0x01, 0x00, 0x00, 0x80, b]);
        expected.push(b);
    }
    frame.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(try_decode(&frame).unwrap(), expected);
}

#[test]
fn linked_matches_reach_exactly_64k_back_across_window_trims() {
    // Interleave uncompressed blocks of awkward sizes with compressed
    // blocks whose only match reaches a chosen distance back into earlier
    // blocks — up to 65535, the farthest an LZ4 offset can express. The
    // history kept for linked blocks must serve every one of them no
    // matter where its internal trim points fall.
    let mut frame = frame_header(&[0x40, 0x40]);
    let mut expected: Vec<u8> = Vec::new();
    let mut state = 0x2545_F491u32;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        state
    };
    let first: Vec<u8> = (0..64 * 1024).map(|_| next() as u8).collect();
    push_raw_block(&mut frame, &first);
    expected.extend_from_slice(&first);
    let offsets = [65535u16, 4, 65534, 4096, 65535, 32768, 1000];
    for round in 0..600 {
        let len = 1 + (next() as usize % 997);
        let raw: Vec<u8> = (0..len).map(|_| next() as u8).collect();
        push_raw_block(&mut frame, &raw);
        expected.extend_from_slice(&raw);

        let offset = offsets[round % offsets.len()];
        let tail = next() as u8;
        push_match_block(&mut frame, offset, tail);
        let start = expected.len() - offset as usize;
        expected.extend_from_within(start..start + 4);
        expected.push(tail);
    }
    frame.extend_from_slice(&[0, 0, 0, 0]);
    assert!(expected.len() > 5 * 64 * 1024);
    assert_eq!(try_decode(&frame).unwrap(), expected);
}

#[test]
fn linked_match_beyond_history_is_rejected() {
    // Only 10 bytes of history exist; an offset of 11 points before the
    // start of the frame.
    let mut frame = frame_header(&[0x40, 0x40]);
    push_raw_block(&mut frame, b"0123456789");
    push_match_block(&mut frame, 11, b'!');
    frame.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(try_decode(&frame), Err(compcol::Error::InvalidDistance));

    // Offset 10 is the oldest byte and is fine.
    let mut frame = frame_header(&[0x40, 0x40]);
    push_raw_block(&mut frame, b"0123456789");
    push_match_block(&mut frame, 10, b'!');
    frame.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(try_decode(&frame).unwrap(), b"01234567890123!");
}

// ─── Linked blocks (default) ─────────────────────────────────────────────

#[test]
fn linked_blocks_back_reference_across_boundary() {
    // Build a payload that's exactly 64 KiB of one filler pattern, then
    // a small amount of the *same* prefix repeated — so the second
    // block's matcher would naturally want to back-reference into the
    // first block's tail.
    let cfg = EncoderConfig {
        block_max_size: BlockMaxSize::Max64KB,
        block_independence: false,
        ..Default::default()
    };
    let mut v = Vec::with_capacity(80 * 1024);
    let pattern = b"ABCDEFGHIJKLMNOP";
    while v.len() < 80 * 1024 {
        v.extend_from_slice(pattern);
    }
    round_trip_with(cfg, &v);
}

/// Linked blocks must compress strictly better than independent blocks when
/// the payload's second block repeats data from the first block's tail —
/// because only linked mode can back-reference across the boundary.
#[test]
fn linked_beats_independent_across_boundary() {
    // First 64 KiB: pseudo-random (so it is not itself very compressible).
    // Second block: a verbatim copy of the first block's last stretch, which
    // only a cross-block reference can exploit.
    let mut first = Vec::with_capacity(64 * 1024);
    let mut state: u32 = 0x1357_9BDF;
    for _ in 0..(64 * 1024) {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        first.push((state >> 16) as u8);
    }
    let mut payload = first.clone();
    // Second block reuses the tail of the first block verbatim.
    payload.extend_from_slice(&first[16 * 1024..]);

    let linked = EncoderConfig {
        block_max_size: BlockMaxSize::Max64KB,
        block_independence: false,
        level: 9,
        ..Default::default()
    };
    let independent = EncoderConfig {
        block_independence: true,
        ..linked
    };

    let enc_linked = encode_with_cfg_chunked(linked, &payload, 8192, 8192);
    let enc_indep = encode_with_cfg_chunked(independent, &payload, 8192, 8192);

    // Both must round-trip.
    round_trip_with(linked, &payload);
    round_trip_with(independent, &payload);

    assert!(
        enc_linked.len() < enc_indep.len(),
        "linked {} should be smaller than independent {}",
        enc_linked.len(),
        enc_indep.len()
    );
}

/// Our linked-block (default) encoder output must decode byte-for-byte through
/// the system `lz4` tool across multiple blocks — the core cross-block
/// reference path.
#[test]
fn cross_tool_linked_multiblock_our_encode_system_decode() {
    if !system_lz4_available() {
        eprintln!("skipping cross-tool test: `lz4` not on PATH");
        return;
    }
    // ~200 KiB so it spans several 64 KiB blocks, with long-range repetition
    // that the linked window exploits across boundaries.
    let unit = b"the quick brown fox jumps over the lazy dog. ".repeat(64);
    let mut payload = Vec::new();
    while payload.len() < 200 * 1024 {
        payload.extend_from_slice(&unit);
    }
    let cfg = EncoderConfig {
        level: 9,
        ..Default::default()
    };
    let encoded = encode_with_cfg_chunked(cfg, &payload, 4096, 4096);
    let decoded = system_decompress(&encoded).expect("system lz4 -dc failed");
    assert_eq!(decoded, payload);
}

// ─── Cross-tool: system `lz4 -dc` ────────────────────────────────────────

fn system_lz4_available() -> bool {
    std::process::Command::new("lz4")
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn system_decompress(input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("lz4")
        .arg("-dc")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.as_mut()?.write_all(input).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout)
}

fn system_compress(input: &[u8]) -> Option<Vec<u8>> {
    use std::io::Write;
    use std::process::{Command, Stdio};

    let mut child = Command::new("lz4")
        .arg("-c")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .ok()?;
    child.stdin.as_mut()?.write_all(input).ok()?;
    let out = child.wait_with_output().ok()?;
    if !out.status.success() {
        return None;
    }
    Some(out.stdout)
}

#[test]
fn cross_tool_our_encode_system_decode() {
    if !system_lz4_available() {
        eprintln!("skipping cross-tool test: `lz4` not on PATH");
        return;
    }
    let payload = b"the quick brown fox jumps over the lazy dog. ".repeat(200);
    let encoded = encode_chunked(&payload, 4096, 4096);
    let decoded = system_decompress(&encoded).expect("system lz4 -dc failed");
    assert_eq!(decoded, payload);
}

#[test]
fn cross_tool_our_encode_system_decode_short() {
    if !system_lz4_available() {
        eprintln!("skipping cross-tool test: `lz4` not on PATH");
        return;
    }
    let payload = b"hello frame format";
    let encoded = encode_chunked(payload, 4096, 4096);
    let decoded = system_decompress(&encoded).expect("system lz4 -dc failed");
    assert_eq!(&decoded[..], payload);
}

#[test]
fn cross_tool_system_encode_our_decode() {
    if !system_lz4_available() {
        eprintln!("skipping cross-tool test: `lz4` not on PATH");
        return;
    }
    let payload = b"the quick brown fox jumps over the lazy dog. ".repeat(200);
    let encoded = system_compress(&payload).expect("system lz4 -c failed");
    let decoded = decode_chunked(&encoded, 4096, 4096);
    assert_eq!(decoded, payload);
}

#[test]
fn cross_tool_system_encode_our_decode_short() {
    if !system_lz4_available() {
        eprintln!("skipping cross-tool test: `lz4` not on PATH");
        return;
    }
    let payload = b"hello frame format";
    let encoded = system_compress(payload).expect("system lz4 -c failed");
    let decoded = decode_chunked(&encoded, 4096, 4096);
    assert_eq!(&decoded[..], payload);
}

#[test]
fn cross_tool_system_encode_large() {
    if !system_lz4_available() {
        eprintln!("skipping cross-tool test: `lz4` not on PATH");
        return;
    }
    // 256 KiB pseudo-random → multi-block when lz4's default is 4 MiB
    // and we keep our decoder agnostic to that.
    let mut payload = Vec::with_capacity(256 * 1024);
    let mut state: u32 = 0xFEED_F00D;
    for _ in 0..(256 * 1024) {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        payload.push((state >> 16) as u8);
    }
    let encoded = system_compress(&payload).expect("system lz4 -c failed");
    let decoded = decode_chunked(&encoded, 4096, 4096);
    assert_eq!(decoded.len(), payload.len());
    assert_eq!(decoded, payload);
}

// ─── Factory ─────────────────────────────────────────────────────────────

// ─── Concatenated and skippable frames ───────────────────────────────────

use compcol::Error;
use compcol::lz4::frame::DecoderConfig;

/// Chunkings every multi-frame stream is decoded with: `(input, output)`
/// slice sizes, down to one byte at a time on either side.
const CHUNKINGS: [(usize, usize); 6] = [
    (1, 1),
    (1, 4096),
    (4096, 1),
    (7, 3),
    (1 << 20, 1 << 20),
    (5, 1 << 16),
];

/// What a decoder made of a stream.
#[derive(Debug, PartialEq)]
struct Decoded {
    out: Vec<u8>,
    /// Input bytes the decoder reported consumed.
    consumed: usize,
    /// Whether `decode` itself reported `StreamEnd` (as opposed to `finish`).
    ended_in_decode: bool,
}

/// Feed `encoded` to `dec` in `in_chunk`-byte slices, draining through an
/// `out_chunk`-byte buffer, until `decode` reports the end or the input
/// runs out; then `finish`.
fn drive(
    dec: &mut Decoder,
    encoded: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<Decoded, Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    let mut consumed = 0;
    let mut ended_in_decode = false;
    'feed: loop {
        let end = (consumed + in_chunk).min(encoded.len());
        loop {
            let before = consumed;
            let (p, status) = dec.decode(&encoded[consumed..end], &mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::StreamEnd => {
                    ended_in_decode = true;
                    break 'feed;
                }
                Status::InputEmpty => break,
                Status::OutputFull => {
                    assert!(
                        consumed > before || p.written > 0,
                        "decode asked to be called again without progress"
                    );
                }
            }
        }
        assert_eq!(consumed, end, "InputEmpty with input left over");
        if end == encoded.len() {
            break;
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        assert_eq!(p.consumed, 0);
        if status == Status::StreamEnd {
            break;
        }
        assert!(p.written > 0, "decoder finish stalled");
    }
    Ok(Decoded {
        out,
        consumed,
        ended_in_decode,
    })
}

/// Decode `stream` with the default (multi-frame) decoder under every
/// chunking and check it yields `expected`, consuming everything.
fn assert_multi_frame(stream: &[u8], expected: &[u8]) {
    for (in_chunk, out_chunk) in CHUNKINGS {
        let got = drive(&mut Decoder::new(), stream, in_chunk, out_chunk)
            .unwrap_or_else(|e| panic!("chunking {in_chunk}/{out_chunk}: {e:?}"));
        assert!(
            got.out == expected,
            "chunking {in_chunk}/{out_chunk}: wrong output ({} bytes, expected {})",
            got.out.len(),
            expected.len()
        );
        assert_eq!(
            got.consumed,
            stream.len(),
            "chunking {in_chunk}/{out_chunk}"
        );
        // The end is only known at `finish`: nothing follows the last frame.
        assert!(!got.ended_in_decode, "chunking {in_chunk}/{out_chunk}");
    }
    assert!(compcol::vec::decompress_to_vec::<LZ4Frame>(stream).unwrap() == expected);
}

/// A skippable frame: magic `0x184D2A50 + nibble`, the payload's length,
/// the payload.
fn skippable_frame(nibble: u8, payload: &[u8]) -> Vec<u8> {
    let mut f = vec![0x50 | nibble, 0x2A, 0x4D, 0x18];
    f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    f.extend_from_slice(payload);
    f
}

/// Compressible text of `n` bytes.
fn words(n: usize) -> Vec<u8> {
    const WORDS: [&[u8]; 6] = [b"lorem ", b"ipsum ", b"dolor ", b"sit ", b"amet ", b"sed "];
    let mut x = 12345u32;
    let mut out = Vec::with_capacity(n + 8);
    while out.len() < n {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12345);
        out.extend_from_slice(WORDS[(x >> 16) as usize % WORDS.len()]);
    }
    out.truncate(n);
    out
}

/// Incompressible bytes.
fn noise(seed: u32, n: usize) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 24) as u8
        })
        .collect()
}

/// Encode one frame at `level`, with or without a content checksum.
fn frame_at(input: &[u8], level: u8, content_checksum: bool) -> Vec<u8> {
    let cfg = EncoderConfig {
        level,
        content_checksum,
        ..Default::default()
    };
    encode_with_cfg_chunked(cfg, input, 4096, 4096)
}

#[test]
fn two_concatenated_frames_decode_as_one() {
    let a = words(3_000);
    let b = noise(9, 2_000);
    for checksums in [(true, true), (false, false), (false, true), (true, false)] {
        let stream = [frame_at(&a, 0, checksums.0), frame_at(&b, 9, checksums.1)].concat();
        assert_multi_frame(&stream, &[&a[..], &b[..]].concat());
    }
}

/// Three frames at different levels and block settings; the middle one
/// spans several linked blocks, the last one declares its content size.
#[test]
fn three_concatenated_frames_decode_as_one() {
    let a = words(5_000);
    let b = words(200_000);
    let frame_b = encode_with_cfg_chunked(
        EncoderConfig {
            level: 12,
            block_checksum: true,
            ..Default::default()
        },
        &b,
        1000,
        4096,
    );
    let frame_c = frame_with_content_size(11, &[b"hello ", b"world"]);
    let stream = [&frame_at(&a, 3, false)[..], &frame_b[..], &frame_c[..]].concat();
    assert_multi_frame(&stream, &[&a[..], &b[..], b"hello world"].concat());
}

#[test]
fn empty_frames_between_and_around_frames() {
    let empty = frame_at(b"", 0, true);
    let bare = frame_at(b"", 0, false);
    assert_multi_frame(&[&empty[..], &bare[..], &empty[..]].concat(), b"");
    let a = frame_at(b"first", 0, false);
    let b = frame_at(&[b'z'; 300], 9, true);
    let stream = [&bare[..], &a[..], &empty[..], &bare[..], &b[..], &empty[..]].concat();
    assert_multi_frame(&stream, &[&b"first"[..], &[b'z'; 300][..]].concat());
}

#[test]
fn skippable_frames_before_between_and_after() {
    let a = words(2_000);
    let b = noise(3, 700);
    let fa = frame_at(&a, 0, false);
    let fb = frame_at(&b, 9, true);
    let expected = [&a[..], &b[..]].concat();
    // A payload that looks like a frame, to show it is not interpreted.
    let decoy = frame_at(b"must not appear in the output", 0, true);
    let big = noise(11, 70_000);

    let before = [&skippable_frame(0, &decoy)[..], &fa[..], &fb[..]].concat();
    assert_multi_frame(&before, &expected);
    let between = [&fa[..], &skippable_frame(7, &big)[..], &fb[..]].concat();
    assert_multi_frame(&between, &expected);
    let after = [&fa[..], &fb[..], &skippable_frame(0xF, &decoy)[..]].concat();
    assert_multi_frame(&after, &expected);
    let everywhere = [
        &skippable_frame(1, b"")[..],
        &skippable_frame(2, b"x")[..],
        &fa[..],
        &skippable_frame(3, &decoy)[..],
        &skippable_frame(4, b"")[..],
        &fb[..],
        &skippable_frame(5, &big)[..],
        &skippable_frame(6, b"")[..],
    ]
    .concat();
    assert_multi_frame(&everywhere, &expected);
    // Every skippable magic.
    for nibble in 0..16 {
        let stream = [&skippable_frame(nibble, b"abc")[..], &fa[..]].concat();
        assert_eq!(
            drive(&mut Decoder::new(), &stream, 4096, 4096).unwrap().out,
            a
        );
    }
    // Nothing but skippable frames: an empty output.
    let only = [
        &skippable_frame(0, &decoy)[..],
        &skippable_frame(1, b"")[..],
    ]
    .concat();
    assert_multi_frame(&only, b"");
}

/// A skippable frame declaring the largest payload costs no memory: the
/// decoder counts the bytes down and keeps none.
#[test]
fn huge_skippable_frame_is_not_buffered() {
    let mut stream = vec![0x5A, 0x2A, 0x4D, 0x18, 0xFF, 0xFF, 0xFF, 0xFF];
    stream.extend_from_slice(&[0u8; 100_000]);
    let mut dec = Decoder::new();
    let mut out = [0u8; 64];
    let (p, status) = dec.decode(&stream, &mut out).unwrap();
    assert_eq!((p.consumed, p.written), (stream.len(), 0));
    assert_eq!(status, Status::InputEmpty);
    // The payload is not all there.
    assert_eq!(dec.finish(&mut out).unwrap_err(), Error::UnexpectedEnd);
}

/// Cut a multi-frame stream at every byte. Only the cuts at a frame
/// boundary decode; in particular no cut inside a later frame returns the
/// earlier frames' content as if it were everything.
#[test]
fn truncated_multi_frame_stream_is_an_error() {
    let a = words(600);
    let b = noise(21, 300);
    let fa = frame_at(&a, 0, false);
    let fb = frame_at(b"hello", 0, true);
    let fc = frame_at(&b, 9, true);
    let skip = skippable_frame(3, b"padding");
    let stream = [&fa[..], &fb[..], &skip[..], &fc[..]].concat();
    let b1 = fa.len();
    let b2 = b1 + fb.len();
    let b3 = b2 + skip.len();
    for cut in 0..=stream.len() {
        let expected: Option<Vec<u8>> = if cut == 0 {
            // No input at all is an empty stream.
            Some(Vec::new())
        } else if cut == b1 {
            Some(a.clone())
        } else if cut == b2 || cut == b3 {
            Some([&a[..], b"hello"].concat())
        } else if cut == stream.len() {
            Some([&a[..], b"hello", &b[..]].concat())
        } else {
            None
        };
        for (in_chunk, out_chunk) in [(1, 1), (4096, 4096)] {
            let got = drive(&mut Decoder::new(), &stream[..cut], in_chunk, out_chunk);
            match &expected {
                Some(expected) => {
                    let got = got.unwrap_or_else(|e| panic!("cut {cut}: {e:?}"));
                    assert!(got.out == *expected, "cut {cut}: wrong output");
                    assert_eq!(got.consumed, cut);
                }
                None => assert_eq!(
                    got.map(|d| d.out.len()),
                    Err(Error::UnexpectedEnd),
                    "cut {cut} of {} (boundaries {b1}, {b2}, {b3})",
                    stream.len()
                ),
            }
        }
        if expected.is_none() {
            assert_eq!(
                compcol::vec::decompress_to_vec::<LZ4Frame>(&stream[..cut]),
                Err(Error::UnexpectedEnd),
                "cut {cut}"
            );
        }
    }
}

/// Bytes after a frame that do not start another one end the stream and
/// stay unconsumed, as with the gzip decoder.
#[test]
fn trailing_bytes_end_the_stream_unconsumed() {
    let a = words(900);
    for checksum in [false, true] {
        let fa = frame_at(&a, 0, checksum);
        let garbage: [&[u8]; 4] = [&[0; 8], b"trailing", &[0xFF], &[0x05, 0x22, 0x4D, 0x18]];
        for garbage in garbage {
            let stream = [&fa[..], garbage].concat();
            for (in_chunk, out_chunk) in CHUNKINGS {
                let got = drive(&mut Decoder::new(), &stream, in_chunk, out_chunk).unwrap();
                assert!(got.out == a);
                assert_eq!(got.consumed, fa.len(), "chunking {in_chunk}/{out_chunk}");
                assert!(got.ended_in_decode, "chunking {in_chunk}/{out_chunk}");
            }
            assert!(compcol::vec::decompress_to_vec::<LZ4Frame>(&stream).unwrap() == a);
        }
    }
}

/// Once the byte after a frame is the first byte of a frame magic, a frame
/// has to follow: a wrong magic is `BadHeader`, an incomplete one
/// `UnexpectedEnd`.
#[test]
fn bad_or_partial_magic_after_a_frame_is_an_error() {
    let cases: [(&[u8], Error); 8] = [
        (&[0x04, 0x22, 0x4D, 0x19], Error::BadHeader),
        (&[0x04, 0, 0, 0, 0, 0], Error::BadHeader),
        (b"Paddings", Error::BadHeader),
        (&[0x50, 0x2A, 0x4D, 0x19, 0, 0, 0, 0], Error::BadHeader),
        (&[0x04], Error::UnexpectedEnd),
        (&[0x04, 0x22, 0x4D], Error::UnexpectedEnd),
        (&[0x5F, 0x2A], Error::UnexpectedEnd),
        // A whole skippable magic, half a length.
        (&[0x50, 0x2A, 0x4D, 0x18, 1, 0], Error::UnexpectedEnd),
    ];
    for checksum in [false, true] {
        let fa = frame_at(b"some content", 0, checksum);
        for (tail, error) in cases {
            let stream = [&fa[..], tail].concat();
            for (in_chunk, out_chunk) in CHUNKINGS {
                assert_eq!(
                    drive(&mut Decoder::new(), &stream, in_chunk, out_chunk).map(|d| d.out.len()),
                    Err(error),
                    "tail {tail:02x?}, chunking {in_chunk}/{out_chunk}"
                );
            }
        }
    }
}

/// Each frame's own checksum and content size are verified, and each
/// starts with an empty window.
#[test]
fn later_frame_is_verified_on_its_own() {
    let a = words(500);
    let fa = frame_at(&a, 0, true);
    let good = frame_at(b"hello", 0, true);
    let mut bad_sum = good.clone();
    *bad_sum.last_mut().unwrap() ^= 1;
    let stream = [&fa[..], &good[..], &bad_sum[..]].concat();
    for (in_chunk, out_chunk) in CHUNKINGS {
        assert_eq!(
            drive(&mut Decoder::new(), &stream, in_chunk, out_chunk).map(|d| d.out.len()),
            Err(Error::ChecksumMismatch)
        );
    }

    // The content count starts over with each frame.
    let exact = frame_with_content_size(5, &[b"hello"]);
    assert_multi_frame(
        &[&fa[..], &exact[..], &exact[..]].concat(),
        &[&a[..], b"hellohello"].concat(),
    );
    let short = frame_with_content_size(6, &[b"hello"]);
    assert_eq!(
        drive(
            &mut Decoder::new(),
            &[&fa[..], &exact[..], &short[..]].concat(),
            4096,
            4096
        )
        .map(|d| d.out.len()),
        Err(Error::Corrupt)
    );

    // A linked frame whose first block reaches back 4 bytes: there is
    // nothing there, whatever the previous frame decoded to.
    let mut reaching = frame_header(&[0x40, 0x40]);
    push_match_block(&mut reaching, 4, b'!');
    reaching.extend_from_slice(&[0, 0, 0, 0]);
    assert_eq!(try_decode(&reaching), Err(Error::InvalidDistance));
    let mut linked = frame_header(&[0x40, 0x40]);
    push_raw_block(&mut linked, b"0123456789");
    linked.extend_from_slice(&[0, 0, 0, 0]);
    let stream = [&linked[..], &reaching[..]].concat();
    for (in_chunk, out_chunk) in CHUNKINGS {
        assert_eq!(
            drive(&mut Decoder::new(), &stream, in_chunk, out_chunk).map(|d| d.out.len()),
            Err(Error::InvalidDistance),
            "chunking {in_chunk}/{out_chunk}"
        );
    }
}

/// `decode` cannot tell a frame boundary from the end of the stream until
/// it sees the next byte; `finish` can.
#[test]
fn decode_reports_the_end_only_when_it_can_know() {
    for checksum in [false, true] {
        let fa = frame_at(b"first", 0, checksum);
        let fb = frame_at(b"second", 0, checksum);
        let mut dec = Decoder::new();
        let mut out = [0u8; 64];
        let (p, status) = dec.decode(&fa, &mut out).unwrap();
        assert_eq!((p.consumed, &out[..p.written]), (fa.len(), &b"first"[..]));
        assert_eq!(status, Status::InputEmpty);
        // Still nothing to go by.
        let (p, status) = dec.decode(&[], &mut out).unwrap();
        assert_eq!((p.consumed, p.written, status), (0, 0, Status::InputEmpty));
        let (p, status) = dec.decode(&fb, &mut out).unwrap();
        assert_eq!((p.consumed, &out[..p.written]), (fb.len(), &b"second"[..]));
        assert_eq!(status, Status::InputEmpty);
        let (p, status) = dec.finish(&mut out).unwrap();
        assert_eq!((p.written, status), (0, Status::StreamEnd));
        // Terminal from here on: more input is not looked at.
        let (p, status) = dec.decode(&fb, &mut out).unwrap();
        assert_eq!((p.consumed, p.written, status), (0, 0, Status::StreamEnd));
        let (p, status) = dec.finish(&mut out).unwrap();
        assert_eq!((p.written, status), (0, Status::StreamEnd));
    }
}

/// With `multi_frame` off the decoder stops at the end of the first frame,
/// consuming not one byte more, whatever follows.
#[test]
fn single_frame_mode_stops_after_the_first_frame() {
    let config = DecoderConfig::default().with_multi_frame(false);
    assert!(DecoderConfig::default().multi_frame);
    let a = words(100_000);
    let hello = frame_at(b"hello", 0, true);
    let tails: [&[u8]; 5] = [
        b"",
        &hello,
        &[0x04],
        &[0x00; 16],
        b"container data that follows",
    ];
    for frame in [frame_at(&a, 0, false), frame_at(&a, 9, true)] {
        for tail in tails {
            let stream = [&frame[..], tail].concat();
            for (in_chunk, out_chunk) in CHUNKINGS {
                let mut dec = Decoder::with_config(config);
                let got = drive(&mut dec, &stream, in_chunk, out_chunk).unwrap();
                assert!(got.out == a, "chunking {in_chunk}/{out_chunk}");
                assert_eq!(got.consumed, frame.len(), "chunking {in_chunk}/{out_chunk}");
                // Known at once, without `finish` and without a look ahead.
                assert!(got.ended_in_decode, "chunking {in_chunk}/{out_chunk}");
                // And it stays ended.
                let mut out = [0u8; 16];
                let (p, status) = dec.decode(&hello, &mut out).unwrap();
                assert_eq!((p.consumed, p.written, status), (0, 0, Status::StreamEnd));
            }
        }
    }

    // Through the `Algorithm` entry points too.
    let stream = [&hello[..], &hello[..]].concat();
    assert_eq!(
        compcol::vec::decompress_to_vec_with::<LZ4Frame>(&stream, config).unwrap(),
        b"hello"
    );
    assert_eq!(
        compcol::vec::decompress_to_vec::<LZ4Frame>(&stream).unwrap(),
        b"hellohello"
    );
    let mut dec = LZ4Frame::decoder_with(config);
    assert_eq!(
        drive(&mut dec, &stream, 4096, 4096).unwrap().consumed,
        hello.len()
    );

    // Skippable frames ahead of the frame are skipped; the one after it is
    // not touched.
    let skip = skippable_frame(2, b"metadata");
    let stream = [&skip[..], &skip[..], &hello[..], &skip[..]].concat();
    for (in_chunk, out_chunk) in CHUNKINGS {
        let got = drive(
            &mut Decoder::with_config(config),
            &stream,
            in_chunk,
            out_chunk,
        )
        .unwrap();
        assert_eq!(got.out, b"hello");
        assert_eq!(got.consumed, 2 * skip.len() + hello.len());
    }
    // A truncated frame is still an error.
    assert_eq!(
        drive(
            &mut Decoder::with_config(config),
            &hello[..hello.len() - 1],
            1,
            1
        ),
        Err(Error::UnexpectedEnd)
    );
}

/// `reset` returns to the start of a stream from anywhere — inside a later
/// frame, inside a skippable frame, after the end — and keeps the
/// configuration.
#[test]
fn reset_restarts_a_multi_frame_decoder() {
    let fa = frame_at(b"first frame", 0, true);
    let fb = frame_at(&words(5_000), 0, true);
    let skip = skippable_frame(0, &[0xAB; 50]);
    let stream = [&fa[..], &fb[..]].concat();
    let mut out = vec![0u8; 1 << 16];
    for stop in [fa.len(), fa.len() + 2, fa.len() + 9, stream.len()] {
        let mut dec = Decoder::new();
        dec.decode(&stream[..stop], &mut out).unwrap();
        dec.reset();
        assert_eq!(
            drive(&mut dec, &fa, 4096, 4096).unwrap().out,
            b"first frame"
        );
    }
    let mut dec = Decoder::new();
    dec.decode(&skip[..20], &mut out).unwrap();
    dec.reset();
    assert_eq!(
        drive(&mut dec, &stream, 1, 1).unwrap().consumed,
        stream.len()
    );
    // After the end, and after an error.
    dec.reset();
    assert_eq!(
        drive(&mut dec, &fa, 4096, 4096).unwrap().out,
        b"first frame"
    );
    dec.reset();
    assert!(drive(&mut dec, b"\x04not a frame", 4096, 4096).is_err());
    dec.reset();
    assert_eq!(
        drive(&mut dec, &fa, 4096, 4096).unwrap().out,
        b"first frame"
    );

    let mut dec = Decoder::with_config(DecoderConfig::default().with_multi_frame(false));
    assert_eq!(
        drive(&mut dec, &stream, 4096, 4096).unwrap().consumed,
        fa.len()
    );
    dec.reset();
    assert_eq!(
        drive(&mut dec, &stream, 4096, 4096).unwrap().consumed,
        fa.len()
    );
}

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("lz4-frame").is_some());
        assert!(factory::decoder_by_name("lz4-frame").is_some());
    }

    #[test]
    fn names_contains_lz4_frame() {
        assert!(factory::names().contains(&"lz4-frame"));
    }

    #[test]
    fn extension_is_lz4() {
        assert_eq!(factory::extension("lz4-frame"), Some("lz4"));
    }
}
