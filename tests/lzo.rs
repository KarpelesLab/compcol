//! Streaming round-trip tests for the LZO1X-1 algorithm.
//!
//! Tests run under the `std` test harness but the library itself is `no_std`.

#![cfg(feature = "lzo")]

use compcol::lzo::{Decoder, Encoder, Lzo};
use compcol::{Algorithm, Decoder as _, Encoder as _};

/// Encode `input` through the streaming trait using the supplied chunk sizes.
fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed_in_chunk = 0;
        while consumed_in_chunk < chunk.len() {
            let p = enc.encode(&chunk[consumed_in_chunk..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed_in_chunk += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                panic!("encoder stalled mid-input");
            }
        }
        i = end;
    }

    loop {
        let p = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled");
        }
    }

    encoded
}

fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed_in_chunk = 0;
        while consumed_in_chunk < chunk.len() {
            let p = dec.decode(&chunk[consumed_in_chunk..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed_in_chunk += p.consumed;
            if p.consumed == 0 && p.written == 0 {
                panic!("decoder stalled mid-input");
            }
        }
        i = end;
    }

    loop {
        let p = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }

    decoded
}

fn round_trip_with_chunks(input: &[u8], in_chunk: usize, out_chunk: usize) {
    let encoded = encode_chunked(input, in_chunk, out_chunk);
    let decoded = decode_chunked(&encoded, in_chunk.max(1), out_chunk.max(1));
    assert_eq!(decoded.len(), input.len(), "round-trip length mismatch");
    assert_eq!(decoded, input, "round-trip content mismatch");
}

fn round_trip(input: &[u8]) {
    let big = input.len().saturating_mul(2).max(1024);
    round_trip_with_chunks(input, big, big);
}

#[test]
fn name_is_lzo() {
    assert_eq!(<Lzo as Algorithm>::NAME, "lzo");
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
fn short_input() {
    round_trip(b"hello, world");
}

#[test]
fn no_compressible_short() {
    round_trip(b"abcdefghijklmnop");
}

#[test]
fn long_run_of_one_byte() {
    // 10 KiB of one byte exercises the LZ77 overlapping-match case.
    let input = vec![b'Z'; 10 * 1024];
    round_trip(&input);
}

#[test]
fn long_run_two_bytes() {
    let mut input = Vec::with_capacity(8192);
    for _ in 0..4096 {
        input.extend_from_slice(b"ab");
    }
    round_trip(&input);
}

#[test]
fn ascii_text_exceeding_64kib() {
    // Repeat a sentence until well past 64 KiB so the streaming wrapper
    // has to split the input across multiple blocks (block size is 48 KiB).
    let sentence = b"the quick brown fox jumps over the lazy dog. ";
    let mut input = Vec::with_capacity(80 * 1024);
    while input.len() < 80 * 1024 {
        input.extend_from_slice(sentence);
    }
    round_trip(&input);

    // Encoded size should be meaningfully smaller than input.
    let encoded = encode_chunked(&input, input.len(), input.len() * 2);
    assert!(
        encoded.len() < input.len() / 2,
        "encoded {} not less than half input {}",
        encoded.len(),
        input.len()
    );
}

#[test]
fn pseudo_random_input() {
    // Tiny LCG, fixed seed; keeps the test dependency-free.
    let mut state: u32 = 0xDEADBEEF;
    let mut input = Vec::with_capacity(8192);
    for _ in 0..8192 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        input.push((state >> 16) as u8);
    }
    round_trip(&input);
}

#[test]
fn chunked_one_byte_at_a_time() {
    // 1-byte buffers on both sides — the acid test.
    let input: Vec<u8> = (0..512u32).map(|i| (i % 7) as u8).collect();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn chunked_one_byte_at_a_time_repetitive() {
    // 1-byte-on-both-sides for a payload that compresses.
    let mut input = Vec::with_capacity(2048);
    for _ in 0..256 {
        input.extend_from_slice(b"abcdefgh");
    }
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn chunked_at_block_boundary() {
    // 128 KiB so it crosses two 48 KiB block boundaries. Feed in chunks
    // that don't align with the boundary.
    let mut input = Vec::with_capacity(128 * 1024);
    let sentence = b"compcol streaming test payload - repeat me. ";
    while input.len() < 128 * 1024 {
        input.extend_from_slice(sentence);
    }
    let encoded = encode_chunked(&input, 7919, 8191);
    let decoded = decode_chunked(&encoded, 7919, 8191);
    assert_eq!(decoded.len(), input.len());
    assert_eq!(decoded, input);
}

#[test]
fn reset_clears_state() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 256];
    let _ = enc
        .encode(b"first run, will be discarded", &mut out)
        .unwrap();
    enc.reset();

    let mut produced = Vec::new();
    let p = enc.encode(b"second run", &mut out).unwrap();
    produced.extend_from_slice(&out[..p.written]);
    loop {
        let p = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..p.written]);
        if p.done {
            break;
        }
        if p.written == 0 {
            panic!("finish stalled");
        }
    }

    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let p = dec.decode(&produced, &mut out).unwrap();
    decoded.extend_from_slice(&out[..p.written]);
    let p = dec.finish(&mut out).unwrap();
    decoded.extend_from_slice(&out[..p.written]);
    assert!(p.done);
    assert_eq!(decoded, b"second run");
}

// ─── cross-validation with python-lzo, if available ──────────────────────
//
// `python-lzo` exposes `lzo.compress(data, level=1, header=True)` which by
// default prepends a small private framing (1 magic byte + 4 big-endian
// length bytes). Passing `header=False` produces the raw LZO1X block —
// which is exactly the payload our `encode_block` / `decode_block` work
// with, modulo our 4-byte block-length framing.
//
// For cross-validation we shell out to a venv that has python-lzo
// installed at a well-known path. If that venv doesn't exist we skip.

fn python_lzo_available() -> bool {
    std::process::Command::new("/tmp/lzovenv/bin/python3")
        .args(["-c", "import lzo"])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Strip our 4-byte framing to extract the inner LZO1X block(s) so we can
/// hand the raw payload to python-lzo. This is only useful for inputs that
/// fit in a single block — beyond `BLOCK_SIZE` the test concatenates
/// multiple blocks which python-lzo wouldn't recognise as a single stream.
fn strip_framing(framed: &[u8]) -> Option<Vec<u8>> {
    if framed.len() < 8 {
        return None;
    }
    let len = u32::from_le_bytes([framed[0], framed[1], framed[2], framed[3]]) as usize;
    if 4 + len > framed.len() {
        return None;
    }
    // Verify the next u32 is the zero terminator (single-block stream).
    let term = &framed[4 + len..];
    if term.len() != 4 || term != [0, 0, 0, 0] {
        return None;
    }
    Some(framed[4..4 + len].to_vec())
}

fn python_lzo_decompress(raw_block: &[u8], expected_len: usize) -> Vec<u8> {
    use std::io::Write;
    let mut child = std::process::Command::new("/tmp/lzovenv/bin/python3")
        .args([
            "-c",
            "import sys, lzo; d=sys.stdin.buffer.read(); n=int(sys.argv[1]); sys.stdout.buffer.write(lzo.decompress(d, False, n))",
            &expected_len.to_string(),
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("spawn python-lzo");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(raw_block)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success(), "python-lzo decompress failed");
    out.stdout
}

fn python_lzo_compress(data: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut child = std::process::Command::new("/tmp/lzovenv/bin/python3")
        .args([
            "-c",
            "import sys, lzo; d=sys.stdin.buffer.read(); sys.stdout.buffer.write(lzo.compress(d, 1, False))",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .spawn()
        .expect("spawn python-lzo");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(data)
        .expect("write stdin");
    let out = child.wait_with_output().expect("wait");
    assert!(out.status.success(), "python-lzo compress failed");
    out.stdout
}

/// Wrap a raw LZO1X block in our framing so the streaming decoder accepts
/// it (length-prefix + payload + zero-terminator).
fn add_framing(raw: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(raw.len() + 8);
    framed.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    framed.extend_from_slice(raw);
    framed.extend_from_slice(&[0, 0, 0, 0]);
    framed
}

#[test]
fn cross_decode_python_lzo_short_text() {
    if !python_lzo_available() {
        eprintln!("skipping: python-lzo not installed in /tmp/lzovenv");
        return;
    }
    let data = b"the quick brown fox jumps over the lazy dog. ".repeat(20);
    let compressed = python_lzo_compress(&data);
    let framed = add_framing(&compressed);
    let decoded = decode_chunked(&framed, 1024, 1024);
    assert_eq!(decoded, data);
}

#[test]
fn cross_decode_python_lzo_random() {
    if !python_lzo_available() {
        eprintln!("skipping: python-lzo not installed in /tmp/lzovenv");
        return;
    }
    let mut state: u32 = 0xABCD0123;
    let mut data = Vec::with_capacity(4096);
    for _ in 0..4096 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        data.push((state >> 16) as u8);
    }
    let compressed = python_lzo_compress(&data);
    let framed = add_framing(&compressed);
    let decoded = decode_chunked(&framed, 1024, 1024);
    assert_eq!(decoded, data);
}

#[test]
fn cross_encode_python_lzo_short_text() {
    if !python_lzo_available() {
        eprintln!("skipping: python-lzo not installed in /tmp/lzovenv");
        return;
    }
    let data = b"the quick brown fox jumps over the lazy dog. ".repeat(20);
    let framed = encode_chunked(&data, data.len(), data.len() * 2);
    let raw = strip_framing(&framed).expect("single-block stream");
    let decoded = python_lzo_decompress(&raw, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn cross_encode_python_lzo_run() {
    if !python_lzo_available() {
        eprintln!("skipping: python-lzo not installed in /tmp/lzovenv");
        return;
    }
    let data = vec![b'A'; 5000];
    let framed = encode_chunked(&data, data.len(), data.len() * 2);
    let raw = strip_framing(&framed).expect("single-block stream");
    let decoded = python_lzo_decompress(&raw, data.len());
    assert_eq!(decoded, data);
}

#[test]
fn fuzz_lcg_round_trip_random() {
    // Round-trip a sampling of prefixes of a 5 KiB LCG-generated buffer.
    // Catches boundary conditions in the state machine at every length
    // in 0..5120 that the spec singles out (literal-run encoding break
    // points at 4, 18, 238, 239, 240; long-distance form at 16384;
    // length-extension at 33, 9, etc.).
    let mut state: u32 = 0x12345678;
    let mut data = Vec::with_capacity(5120);
    for _ in 0..5120 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        data.push((state >> 16) as u8);
    }
    for prefix_len in [
        0, 1, 2, 3, 4, 5, 16, 17, 18, 19, 20, 21, 22, 64, 100, 238, 239, 240, 500, 1000, 2048,
        4096, 5120,
    ] {
        round_trip(&data[..prefix_len]);
    }
}

#[test]
fn fuzz_repetitive_round_trip() {
    // Pseudo-random "compressible" inputs: bytes drawn from a small
    // alphabet so the matcher finds real matches. Tests every prefix
    // length at several spec-significant boundaries.
    let mut state: u32 = 0xFEEDF00D;
    let alphabet = b"abcdefghij";
    let mut data = Vec::with_capacity(5120);
    for _ in 0..5120 {
        state = state.wrapping_mul(1_103_515_245).wrapping_add(12345);
        let i = ((state >> 16) as usize) % alphabet.len();
        data.push(alphabet[i]);
    }
    for prefix_len in [
        0, 1, 2, 3, 4, 5, 16, 17, 18, 19, 20, 21, 22, 64, 100, 238, 239, 240, 500, 1000, 2048,
        4096, 5120,
    ] {
        round_trip(&data[..prefix_len]);
    }
}

#[test]
fn long_distance_match() {
    // Force the encoder to use the M4 (16384..49151) form: place a
    // distinguishable marker, fill with > 16384 bytes of filler, then
    // reinsert the marker. The matcher should pick up the repeat at a
    // distance > 16384.
    let mut data = Vec::with_capacity(40 * 1024);
    let marker =
        b"MARKER_PAYLOAD_WITH_SOME_DISTINCT_CONTENT_THAT_WILL_BE_MATCHED_AT_LONG_DISTANCE_";
    data.extend_from_slice(marker);
    let filler = b"the quick brown fox jumps over the lazy dog. ";
    while data.len() < 17 * 1024 + marker.len() {
        data.extend_from_slice(filler);
    }
    data.extend_from_slice(marker);
    while data.len() < 40 * 1024 {
        data.extend_from_slice(filler);
    }
    round_trip(&data);
}

#[test]
fn fuzz_every_prefix_of_lorem() {
    // Every prefix length from 0..16384 of a long Lorem ipsum text.
    let lorem = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. ";
    let mut data = Vec::with_capacity(16384);
    while data.len() < 16384 {
        data.extend_from_slice(lorem);
    }
    data.truncate(16384);
    for prefix_len in (0..=16384).step_by(7) {
        round_trip(&data[..prefix_len]);
    }
    // Plus the very-last position to cover the boundary.
    round_trip(&data[..]);
}

#[test]
fn length_extension_boundary_values() {
    // Inputs sized to hit every length-extension boundary exactly: 33,
    // 34, 287, 288, 289, 542, 543 in the M3 form. These caught an
    // earlier off-by-one in the extension encoder.
    let prefix = b"unique-prefix-1234567890-end";
    for &repeat_len in &[33usize, 34, 287, 288, 289, 542, 543, 800, 1000, 2048, 4096] {
        let mut data = Vec::with_capacity(prefix.len() + repeat_len);
        data.extend_from_slice(prefix);
        // Copy bytes from the prefix so the matcher finds a long match.
        let pre_len = prefix.len();
        for i in 0..repeat_len {
            data.push(prefix[i % pre_len]);
        }
        round_trip(&data);
    }
}

#[test]
fn long_distance_match_repeated_marker() {
    // Variant where the marker is itself a repeated subpattern so the
    // greedy matcher might find a long M4 match at an offset > 16384.
    let mut data = Vec::with_capacity(40 * 1024);
    let lorem = b"the quick brown fox jumps over the lazy dog. ";
    while data.len() < 17 * 1024 {
        data.extend_from_slice(lorem);
    }
    let marker = b"MARKER_PAYLOAD_WITH_SOME_DISTINCT_CONTENT_";
    for _ in 0..20 {
        data.extend_from_slice(marker);
    }
    while data.len() < 40 * 1024 {
        data.extend_from_slice(lorem);
    }
    round_trip(&data);
}

#[test]
fn fuzz_every_prefix_of_repetitive() {
    // The truly thorough check: every prefix length from 0..2048 of a
    // small-alphabet input. Slow under debug but a few hundred ms in
    // release; still fast enough to keep in the default test set.
    let mut state: u32 = 0xCAFEBABE;
    let mut data = Vec::with_capacity(2048);
    for _ in 0..2048 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let nibble = ((state >> 16) & 0xF) as u8;
        data.push(b'a' + nibble);
    }
    for prefix_len in 0..=2048 {
        round_trip(&data[..prefix_len]);
    }
}

#[test]
fn lorem_16kib_ratio_reasonable() {
    let lorem = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id est laborum. ";
    let mut data = Vec::with_capacity(16 * 1024);
    while data.len() < 16 * 1024 {
        data.extend_from_slice(lorem);
    }
    data.truncate(16 * 1024);

    let framed = encode_chunked(&data, data.len(), data.len() * 2);
    // The raw block (between framing) should be roughly the same size
    // python-lzo gets, but we don't insist on matching exactly — our
    // greedy matcher is simpler.
    let raw_size = framed.len() - 8;
    eprintln!(
        "lzo 16 KiB Lorem: {} bytes (framed: {})",
        raw_size,
        framed.len()
    );
    // Sanity: at least 10:1 ratio for this highly repetitive corpus.
    assert!(
        raw_size < data.len() / 10,
        "compression too poor: {} for {} input",
        raw_size,
        data.len()
    );

    // Round-trip.
    let decoded = decode_chunked(&framed, framed.len(), data.len());
    assert_eq!(decoded, data);
}

#[test]
fn cross_encode_python_lzo_random() {
    if !python_lzo_available() {
        eprintln!("skipping: python-lzo not installed in /tmp/lzovenv");
        return;
    }
    let mut state: u32 = 0xC0FFEE;
    let mut data = Vec::with_capacity(2048);
    for _ in 0..2048 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        data.push((state >> 16) as u8);
    }
    let framed = encode_chunked(&data, data.len(), data.len() * 2);
    let raw = strip_framing(&framed).expect("single-block stream");
    let decoded = python_lzo_decompress(&raw, data.len());
    assert_eq!(decoded, data);
}
