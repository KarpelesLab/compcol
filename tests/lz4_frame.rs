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
