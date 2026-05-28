#![cfg(any())] // TODO(v0.3): port to new (Progress, Status) API
//! Streaming round-trip + decode-only tests for the Zstd algorithm.
//!
//! See `src/zstd/mod.rs` for the supported subset (Raw_Block / RLE_Block
//! decoding, Raw_Block-only encoding). Tests run under the `std` test
//! harness but the library itself is `no_std`.

#![cfg(feature = "zstd")]

use compcol::zstd::{Decoder, Encoder, Zstd};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error};

// ─── helpers ─────────────────────────────────────────────────────────────

/// Encode `input` and return the full zstd-framed bytes. `in_chunk` and
/// `out_chunk` exercise streaming: feed input in slices of `in_chunk` bytes
/// and pull output through a buffer of `out_chunk` bytes.
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
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("encoder finish stalled");
        }
    }

    encoded
}

/// Inverse of `encode_chunked` — must accept any valid streaming chunking.
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
                // Decoder may legitimately stall once it has consumed all
                // useful bytes of the input chunk (e.g. it's reached `Done`).
                // Break this inner loop so the outer one advances `i`.
                break;
            }
        }
        i = end;
    }

    loop {
        let p = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            panic!("decoder finish stalled");
        }
    }

    decoded
}

fn round_trip(input: &[u8]) {
    // Pick generously-sized buffers — exhaustive small-buffer chunking is in
    // its own test below.
    let encoded = encode_chunked(input, input.len().max(1), input.len().max(64) * 2 + 32);
    let decoded = decode_chunked(&encoded, encoded.len().max(1), input.len().max(64) * 2);
    assert_eq!(
        decoded,
        input,
        "round-trip mismatch (input len = {})",
        input.len()
    );
}

// ─── identity / smoke ────────────────────────────────────────────────────

#[test]
fn name_is_zstd() {
    assert_eq!(<Zstd as Algorithm>::NAME, "zstd");
}

#[test]
fn empty_input_round_trip() {
    round_trip(&[]);
}

#[test]
fn short_input_round_trip() {
    round_trip(b"hello, zstd");
}

#[test]
fn medium_input_round_trip() {
    // Mixed byte values so a real compressor would have something to chew on;
    // our encoder will still copy it through verbatim.
    let input: Vec<u8> = (0u32..4096).map(|i| ((i * 31) ^ (i >> 3)) as u8).collect();
    round_trip(&input);
}

#[test]
fn round_trip_64_kib_pseudo_random() {
    let input = lcg_bytes(0x1234_5678, 64 * 1024);
    round_trip(&input);
}

#[test]
fn round_trip_1_mib_pseudo_random() {
    let input = lcg_bytes(0xDEAD_BEEF, 1024 * 1024);
    round_trip(&input);
}

#[test]
fn chunked_one_byte_at_a_time() {
    // The acid test: 1-byte buffers on both input and output, on both sides.
    let input: Vec<u8> = (0..512u32).map(|i| (i % 7) as u8).collect();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[test]
fn reset_clears_encoder_state() {
    let mut enc = Encoder::new();
    let mut out = vec![0u8; 256];
    let _ = enc.encode(b"first batch", &mut out).unwrap();
    enc.reset();

    // After reset, encoding a fresh input should produce a complete frame
    // identical to one produced from a freshly-constructed encoder.
    let mut produced = Vec::new();
    let p = enc.encode(b"second", &mut out).unwrap();
    produced.extend_from_slice(&out[..p.written]);
    loop {
        let pf = enc.finish(&mut out).unwrap();
        produced.extend_from_slice(&out[..pf.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if pf.written == 0 {
            panic!("stall");
        }
    }

    let mut dec = Decoder::new();
    let mut decoded = vec![0u8; 64];
    let pd = dec.decode(&produced, &mut decoded).unwrap();
    let mut total = pd.written;
    loop {
        let pdf = dec.finish(&mut decoded[total..]).unwrap();
        total += pdf.written;
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if pdf.written == 0 {
            panic!("decoder stall");
        }
    }
    assert_eq!(&decoded[..total], b"second");
}

#[test]
fn reset_clears_decoder_state() {
    let frame_a = encode_chunked(b"alpha", 64, 64);
    let frame_b = encode_chunked(b"beta", 64, 64);

    let mut dec = Decoder::new();
    let mut out = vec![0u8; 32];
    // Decode frame_a fully.
    let pa = dec.decode(&frame_a, &mut out).unwrap();
    let mut ta = pa.written;
    loop {
        let pf = dec.finish(&mut out[ta..]).unwrap();
        ta += pf.written;
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if pf.written == 0 {
            panic!("stall");
        }
    }
    assert_eq!(&out[..ta], b"alpha");

    // Reset and decode frame_b — without reset, the decoder would still be
    // in `Done` and refuse to start over.
    dec.reset();
    let pb = dec.decode(&frame_b, &mut out).unwrap();
    let mut tb = pb.written;
    loop {
        let pf = dec.finish(&mut out[tb..]).unwrap();
        tb += pf.written;
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if pf.written == 0 {
            panic!("stall");
        }
    }
    assert_eq!(&out[..tb], b"beta");
}

// ─── decoder: hand-built fixtures ────────────────────────────────────────

/// Construct a minimal valid Zstd frame with a single Last_Block Raw_Block.
/// Used to exercise the decoder against bytes the encoder didn't produce.
fn build_raw_frame(payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]); // magic
    f.push(0x00); // FHD: no FCS, SS=0, no checksum, no dict
    f.push(0x50); // WD: Exp=10, Mant=0 → 1 KiB window
    // Block_Header: 24-bit LE. Last=1, Type=0 (Raw), Size=payload.len().
    let bh: u32 = 1 | ((payload.len() as u32) << 3);
    f.push((bh & 0xFF) as u8);
    f.push(((bh >> 8) & 0xFF) as u8);
    f.push(((bh >> 16) & 0xFF) as u8);
    f.extend_from_slice(payload);
    f
}

/// Construct a minimal valid Zstd frame with a single Last_Block RLE_Block.
fn build_rle_frame(value: u8, count: u32) -> Vec<u8> {
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x00);
    f.push(0x50);
    // Block_Header: Last=1, Type=1 (RLE), Size=count.
    let bh: u32 = 1 | (1u32 << 1) | (count << 3);
    f.push((bh & 0xFF) as u8);
    f.push(((bh >> 8) & 0xFF) as u8);
    f.push(((bh >> 16) & 0xFF) as u8);
    f.push(value);
    f
}

#[test]
fn decode_hand_built_raw_block() {
    let frame = build_raw_frame(b"hello world");
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 32];
    let p = dec.decode(&frame, &mut out).unwrap();
    let mut total = p.written;
    loop {
        let pf = dec.finish(&mut out[total..]).unwrap();
        total += pf.written;
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if pf.written == 0 {
            panic!("stall");
        }
    }
    assert_eq!(&out[..total], b"hello world");
}

#[test]
fn decode_hand_built_rle_block() {
    let frame = build_rle_frame(b'x', 17);
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 32];
    let p = dec.decode(&frame, &mut out).unwrap();
    let mut total = p.written;
    loop {
        let pf = dec.finish(&mut out[total..]).unwrap();
        total += pf.written;
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if pf.written == 0 {
            panic!("stall");
        }
    }
    assert_eq!(&out[..total], &vec![b'x'; 17][..]);
}

#[test]
fn decode_hand_built_rle_block_streaming_output() {
    // RLE expansion drives the output buffer; verify it streams correctly
    // when the output is much smaller than the run length.
    let frame = build_rle_frame(b'q', 500);
    let mut dec = Decoder::new();
    let mut total = Vec::new();
    let mut out = [0u8; 32];
    let mut input_pos = 0;
    loop {
        let p = dec.decode(&frame[input_pos..], &mut out).unwrap();
        total.extend_from_slice(&out[..p.written]);
        input_pos += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let pf = dec.finish(&mut out).unwrap();
        total.extend_from_slice(&out[..pf.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if pf.written == 0 {
            panic!("stall");
        }
    }
    assert_eq!(total, vec![b'q'; 500]);
}

#[test]
fn decode_rejects_bad_magic() {
    let mut bad = build_raw_frame(b"x");
    bad[0] = 0; // corrupt magic
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(&bad, &mut out).unwrap_err();
    assert_eq!(err, Error::BadHeader);
}

#[test]
fn decode_rejects_checksum_flag() {
    // Build a frame with Content_Checksum_Flag set (bit 2). We can't
    // actually verify the checksum (no XXH64), so the decoder must refuse.
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x04); // FHD: Content_Checksum_Flag = 1
    f.push(0x50); // WD
    // (no need to construct blocks — decoder bails at FHD)
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(&f, &mut out).unwrap_err();
    assert_eq!(err, Error::Unsupported);
}

#[test]
fn decode_rejects_reserved_fhd_bit() {
    // FHD bit 3 (Reserved) must be zero.
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x08); // FHD: Reserved bit set
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(&f, &mut out).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn decode_rejects_reserved_block_type() {
    // Build a frame with a single block whose Block_Type field is 3
    // (Reserved). The decoder should bail at the block-header parse.
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x00); // FHD
    f.push(0x50); // WD
    // BH: Last=1, Type=3 (reserved), Size=0.
    let bh: u32 = 1 | (3u32 << 1);
    f.push((bh & 0xFF) as u8);
    f.push(((bh >> 8) & 0xFF) as u8);
    f.push(((bh >> 16) & 0xFF) as u8);
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(&f, &mut out).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn decode_rejects_malformed_compressed_block() {
    // Build a frame announcing a 4-byte Compressed_Block whose literals
    // header advertises a Compressed_Literals_Block with garbage Huffman
    // tree data. The decoder should bail with Corrupt.
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x00);
    f.push(0x50);
    // BH: Last=1, Type=2 (Compressed), Size=4.
    let bh: u32 = 1 | (2u32 << 1) | (4u32 << 3);
    f.push((bh & 0xFF) as u8);
    f.push(((bh >> 8) & 0xFF) as u8);
    f.push(((bh >> 16) & 0xFF) as u8);
    // LHD = 0x02 → Compressed_Literals_Block, SF=00 (3-byte header total),
    // followed by some garbage that won't form a valid Huffman tree.
    f.push(0x02);
    f.push(0xFF);
    f.push(0xFF);
    f.push(0xFF);
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(&f, &mut out).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

#[test]
fn decode_truncated_frame_unexpected_end() {
    // Magic + FHD only, then nothing — decoder should return UnexpectedEnd
    // when the caller signals end-of-input via `finish`.
    let f = vec![0x28, 0xB5, 0x2F, 0xFD, 0x00];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let p = dec.decode(&f, &mut out).unwrap();
    assert_eq!(p.consumed, 5);
    assert_eq!(p.written, 0);
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn decode_known_good_zstd_fixture_no_checksum_raw_block() {
    // Captured from `printf hello | zstd --no-check -c`:
    //   28 B5 2F FD 00 58 29 00 00 68 65 6C 6C 6F
    // Layout:
    //   magic = 28 B5 2F FD
    //   FHD   = 0x00 — no FCS, SS=0, no checksum, no dict
    //   WD    = 0x58
    //   block header 29 00 00 → Last=1, Type=0 (Raw), Size=5
    //   payload "hello"
    //
    // This is exactly the subset our decoder handles, so it should round-trip
    // back to "hello".
    let fixture: &[u8] = &[
        0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x58, 0x29, 0x00, 0x00, 0x68, 0x65, 0x6C, 0x6C, 0x6F,
    ];
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 32];
    let p = dec.decode(fixture, &mut out).unwrap();
    let mut total = p.written;
    loop {
        let pf = dec.finish(&mut out[total..]).unwrap();
        total += pf.written;
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if pf.written == 0 {
            panic!("stall");
        }
    }
    assert_eq!(&out[..total], b"hello");
}

#[test]
fn decode_known_good_zstd_fixture_with_checksum_unsupported() {
    // Captured from `printf hello | zstd -c`:
    //   28 B5 2F FD 04 58 29 00 00 68 65 6C 6C 6F A3 6D 9F 88
    // Layout:
    //   magic = 28 B5 2F FD
    //   FHD   = 0x04 — Content_Checksum_Flag set, all others zero
    //   WD    = 0x58
    //   block header 29 00 00 → Last=1, Type=0 (Raw), Size=5
    //   payload 68 65 6C 6C 6F = "hello"
    //   content checksum A3 6D 9F 88 = low 32 bits of XXH64("hello")
    //
    // Our subset decoder doesn't ship XXH64, so the Content_Checksum_Flag
    // makes this frame Unsupported. A future implementation that adds XXH64
    // (or that disables checksum validation) could decode "hello".
    let fixture: &[u8] = &[
        0x28, 0xB5, 0x2F, 0xFD, 0x04, 0x58, 0x29, 0x00, 0x00, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0xA3,
        0x6D, 0x9F, 0x88,
    ];
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 64];
    match dec.decode(fixture, &mut out) {
        Err(Error::Unsupported) => {
            // Expected outcome.
        }
        Ok(_p) => {
            // A future version that implements XXH64 could accept this. We
            // don't assert any specific output bytes here.
        }
        Err(other) => panic!("unexpected error from real zstd fixture: {:?}", other),
    }
}

#[test]
fn decode_short_compressed_block_too_small() {
    // A Compressed_Block needs at least a literals header byte and a
    // sequence-count byte — a 1-byte body cannot be valid.
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x50]);
    let bh: u32 = 1 | (2u32 << 1) | (1u32 << 3); // Last=1, Type=2, Size=1
    f.push((bh & 0xFF) as u8);
    f.push(((bh >> 8) & 0xFF) as u8);
    f.push(((bh >> 16) & 0xFF) as u8);
    f.push(0x00);
    let mut dec = Decoder::new();
    let mut out = vec![0u8; 16];
    let err = dec.decode(&f, &mut out).unwrap_err();
    assert_eq!(err, Error::Corrupt);
}

// ─── encoder: frame shape sanity ─────────────────────────────────────────

#[test]
fn encoder_emits_valid_frame_header() {
    let encoded = encode_chunked(b"x", 16, 16);
    // First 4 bytes are the magic.
    assert_eq!(&encoded[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
    // FHD should be 0x00 (see module docs).
    assert_eq!(encoded[4], 0x00);
    // WD = 0x70 (Exp=14, Mant=0 → 16 KiB).
    assert_eq!(encoded[5], 0x70);
    // Block_Header bytes 6..9 should encode Last=1, Type=0 (Raw), Size=1.
    let bh = (encoded[6] as u32) | ((encoded[7] as u32) << 8) | ((encoded[8] as u32) << 16);
    let last = bh & 1;
    let btype = (bh >> 1) & 0b11;
    let bsize = (bh >> 3) & 0x1F_FFFF;
    assert_eq!(last, 1);
    assert_eq!(btype, 0);
    assert_eq!(bsize, 1);
    // Payload byte.
    assert_eq!(encoded[9], b'x');
    assert_eq!(encoded.len(), 10);
}

#[test]
fn empty_encode_emits_empty_last_block() {
    // finish() with no input still produces a complete frame: magic + FHD +
    // WD + a single Last_Block Raw_Block of size 0.
    let encoded = encode_chunked(&[], 16, 16);
    assert_eq!(&encoded[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
    assert_eq!(encoded[4], 0x00);
    assert_eq!(encoded[5], 0x70);
    // 3-byte block header with Last=1, Type=0, Size=0 → bytes 01 00 00.
    assert_eq!(&encoded[6..9], &[0x01, 0x00, 0x00]);
    assert_eq!(encoded.len(), 9);
}

// ─── decode-only against system zstd ─────────────────────────────────────

#[cfg(unix)]
fn tool_available(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

#[cfg(unix)]
fn zstd_encode(input: &[u8]) -> Vec<u8> {
    use std::io::Write;
    let mut child = std::process::Command::new("zstd")
        .args(["--no-check", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("spawn zstd");
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin.write_all(input).unwrap();
    }
    let out = child.wait_with_output().unwrap();
    assert!(out.status.success(), "zstd failed");
    out.stdout
}

#[cfg(unix)]
fn decode_all(encoded: &[u8]) -> Vec<u8> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; 8192];
    let mut input_pos = 0usize;
    loop {
        let p = match dec.decode(&encoded[input_pos..], &mut buf) {
            Ok(p) => p,
            Err(e) => {
                eprintln!(
                    "decode err {:?} at input_pos {} (decoded so far {})",
                    e,
                    input_pos,
                    decoded.len()
                );
                panic!("{:?}", e);
            }
        };
        decoded.extend_from_slice(&buf[..p.written]);
        input_pos += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            break;
        }
    }
    loop {
        let pf = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..pf.written]);
        if matches!(_s, compcol::Status::StreamEnd) {
            break;
        }
        if pf.written == 0 {
            panic!("decoder finish stalled");
        }
    }
    decoded
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_empty() {
    if !tool_available("zstd") {
        return;
    }
    let encoded = zstd_encode(b"");
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, b"");
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_hello() {
    if !tool_available("zstd") {
        return;
    }
    let encoded = zstd_encode(b"hello world\n");
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, b"hello world\n");
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_lorem_4k() {
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(4096);
    while input.len() < 4096 {
        input.extend_from_slice(snippet);
    }
    input.truncate(4096);
    let encoded = zstd_encode(&input);
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn debug_huff_tree_weights_lorem_4k() {
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(4096);
    while input.len() < 4096 {
        input.extend_from_slice(snippet);
    }
    input.truncate(4096);
    let encoded = zstd_encode(&input);
    let body_offset = 9;
    let bh = (encoded[6] as u32) | ((encoded[7] as u32) << 8) | ((encoded[8] as u32) << 16);
    let bsize = ((bh >> 3) & 0x1F_FFFF) as usize;
    if (bh >> 1) & 0b11 != 2 {
        return;
    }
    let body = &encoded[body_offset..body_offset + bsize];
    // skip 3-byte literals header
    let lit_payload = &body[3..];
    let weights = compcol::zstd::_internal_test_api::huff_tree_weights_for_test(lit_payload)
        .expect("weights decode");
    eprintln!("decoded {} weights", weights.len());
    eprintln!("weights: {:?}", weights);
}

#[cfg(unix)]
#[test]
fn debug_literals_only_lorem_4k() {
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(4096);
    while input.len() < 4096 {
        input.extend_from_slice(snippet);
    }
    input.truncate(4096);
    let encoded = zstd_encode(&input);
    let body_offset = 9;
    let bh = (encoded[6] as u32) | ((encoded[7] as u32) << 8) | ((encoded[8] as u32) << 16);
    let bsize = ((bh >> 3) & 0x1F_FFFF) as usize;
    let btype = (bh >> 1) & 0b11;
    eprintln!("first block: type={}, size={}", btype, bsize);
    if btype != 2 {
        return;
    }
    let body = &encoded[body_offset..body_offset + bsize];
    eprintln!("body[..16] = {:02x?}", &body[..body.len().min(16)]);
    let (lits, used) = compcol::zstd::_internal_test_api::decode_literals_for_test(body).unwrap();
    eprintln!(
        "literals: {} bytes (consumed {} of {}); first 64 as str: {:?}",
        lits.len(),
        used,
        body.len(),
        std::str::from_utf8(&lits[..lits.len().min(64)])
    );
}

/// Isolated literals-section test against the body of a Compressed_Block
/// produced by the system `zstd` CLI. Useful when full-decode tests fail —
/// pinpoints whether the bug is in literals or sequences.
#[cfg(unix)]
#[test]
fn debug_literals_only_lorem_200() {
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
    let mut input = Vec::with_capacity(200);
    while input.len() < 200 {
        input.extend_from_slice(snippet);
    }
    input.truncate(200);
    let encoded = zstd_encode(&input);
    // Frame layout: magic(4) + FHD(1) + WD(1) + BH(3) + body.
    let body_offset = 9;
    let bh = (encoded[6] as u32) | ((encoded[7] as u32) << 8) | ((encoded[8] as u32) << 16);
    let bsize = ((bh >> 3) & 0x1F_FFFF) as usize;
    let btype = (bh >> 1) & 0b11;
    eprintln!("first block: type={}, size={}", btype, bsize);
    if btype != 2 {
        eprintln!("not a compressed block ({}), skipping", btype);
        return;
    }
    let body = &encoded[body_offset..body_offset + bsize];
    eprintln!("body[..16] = {:02x?}", &body[..body.len().min(16)]);
    match compcol::zstd::_internal_test_api::decode_literals_for_test(body) {
        Ok((lits, used)) => {
            eprintln!(
                "literals: {} bytes (consumed {} of body); first 32: {:?}",
                lits.len(),
                used,
                &lits[..lits.len().min(32)]
            );
        }
        Err(e) => panic!("literals decode failed: {:?}", e),
    }
}

#[test]
fn check_default_ll_table_entries() {
    let entries = compcol::zstd::_internal_test_api::default_ll_entries();
    // RFC 8478 Appendix A.1 worked example: state 0 → symbol 0,
    // state 16 → symbol 24. (More cross-checks would be ideal but the RFC
    // truncates the table in the version we can fetch.)
    eprintln!("entries[0] = {:?}", entries[0]);
    eprintln!("entries[16] = {:?}", entries[16]);
    eprintln!("entries[20] = {:?}", entries[20]);
    eprintln!("entries[32] = {:?}", entries[32]);
    eprintln!("entries[63] = {:?}", entries[63]);
    assert_eq!(entries[0].0, 0, "state 0 should be symbol 0");
    assert_eq!(entries[16].0, 24, "state 16 should be symbol 24");
    let mle = compcol::zstd::_internal_test_api::default_ml_entries();
    eprintln!("ML[20] = {:?}", mle[20]);
    let ofe = compcol::zstd::_internal_test_api::default_of_entries();
    eprintln!("OF[10] = {:?}", ofe[10]);
}

#[cfg(unix)]
#[test]
fn debug_sequences_lorem_200() {
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
    let mut input = Vec::with_capacity(200);
    while input.len() < 200 {
        input.extend_from_slice(snippet);
    }
    input.truncate(200);
    let encoded = zstd_encode(&input);
    let body_offset = 9;
    let bh = (encoded[6] as u32) | ((encoded[7] as u32) << 8) | ((encoded[8] as u32) << 16);
    let bsize = ((bh >> 3) & 0x1F_FFFF) as usize;
    let btype = (bh >> 1) & 0b11;
    if btype != 2 {
        return;
    }
    let body = &encoded[body_offset..body_offset + bsize];
    let (_lits, used) = compcol::zstd::_internal_test_api::decode_literals_for_test(body).unwrap();
    let seq = &body[used..];
    eprintln!("sequence section ({} bytes): {:02x?}", seq.len(), seq);
    match compcol::zstd::_internal_test_api::decode_sequences_for_test(seq) {
        Ok(n) => eprintln!("decoded {} sequences", n),
        Err(e) => panic!("sequences decode failed: {:?}", e),
    }
}

/// Same as above but also runs the sequences-and-execute pass.
#[cfg(unix)]
#[test]
fn debug_full_block_lorem_200() {
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. ";
    let mut input = Vec::with_capacity(200);
    while input.len() < 200 {
        input.extend_from_slice(snippet);
    }
    input.truncate(200);
    let encoded = zstd_encode(&input);
    let body_offset = 9;
    let bh = (encoded[6] as u32) | ((encoded[7] as u32) << 8) | ((encoded[8] as u32) << 16);
    let bsize = ((bh >> 3) & 0x1F_FFFF) as usize;
    let btype = (bh >> 1) & 0b11;
    if btype != 2 {
        return;
    }
    let body = &encoded[body_offset..body_offset + bsize];
    match compcol::zstd::_internal_test_api::decode_compressed_block_body(body) {
        Ok(out) => {
            eprintln!(
                "decoded block: {} bytes; first 32: {:?}",
                out.len(),
                &out[..out.len().min(32)]
            );
            assert_eq!(out.len(), input.len());
            assert_eq!(out, input);
        }
        Err(e) => panic!("block decode failed: {:?}", e),
    }
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_lorem_32k() {
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(32 * 1024);
    while input.len() < 32 * 1024 {
        input.extend_from_slice(snippet);
    }
    input.truncate(32 * 1024);
    let encoded = zstd_encode(&input);
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_pseudo_random_64k() {
    // Pseudo-random — likely encoded as a Raw_Block (high entropy), but it
    // still exercises the frame parser end-to-end.
    if !tool_available("zstd") {
        return;
    }
    let input = lcg_bytes(0xCAFEBABE, 64 * 1024);
    let encoded = zstd_encode(&input);
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_rle_friendly() {
    // 5000 'a's — zstd will collapse this to an RLE block at the block layer,
    // or to a tiny compressed block with mostly LZ77 sequences.
    if !tool_available("zstd") {
        return;
    }
    let input = vec![b'a'; 5000];
    let encoded = zstd_encode(&input);
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_pangram_repeat() {
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"The quick brown fox jumps over the lazy dog.\n";
    let mut input = Vec::new();
    while input.len() < 4500 {
        input.extend_from_slice(snippet);
    }
    input.truncate(4500);
    let encoded = zstd_encode(&input);
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_long_rle() {
    // 50 KiB of 'a' — likely spans multiple blocks; tests Repeat_Mode for
    // sequence tables across blocks.
    if !tool_available("zstd") {
        return;
    }
    let input = vec![b'a'; 50 * 1024];
    let encoded = zstd_encode(&input);
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_sweep_abc_sizes() {
    // Sweep through many input sizes to exercise FSE/Huffman edge cases.
    if !tool_available("zstd") {
        return;
    }
    for n in [
        5usize, 10, 50, 100, 200, 500, 1000, 2000, 5000, 10000, 50000,
    ] {
        let snippet = b"abc";
        let mut input = Vec::with_capacity(n * snippet.len());
        for _ in 0..n {
            input.extend_from_slice(snippet);
        }
        let encoded = zstd_encode(&input);
        let decoded = decode_all(&encoded);
        assert_eq!(decoded, input, "mismatch for n={}", n);
    }
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_streaming_byte_by_byte() {
    // Feed a Compressed_Block-bearing frame to the decoder one byte at a
    // time. Ensures the buffering path for compressed blocks works under
    // tight streaming constraints.
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"abcdefghij" as &[u8];
    let mut input = Vec::with_capacity(4096);
    while input.len() < 4096 {
        input.extend_from_slice(snippet);
    }
    input.truncate(4096);
    let encoded = zstd_encode(&input);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_tiny_rle_pattern() {
    // 31 'a's — small enough that zstd may use Predefined_Mode tables and
    // RLE_Literals_Block. Edge case for tiny-block decoding.
    if !tool_available("zstd") {
        return;
    }
    let input = vec![b'a'; 31];
    let encoded = zstd_encode(&input);
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_diverse_300k() {
    // 300 KB of diverse text — likely produces multiple blocks (≤128 KiB
    // each), exercising Treeless_Literals_Block reuse across blocks.
    if !tool_available("zstd") {
        return;
    }
    let words: &[&[u8]] = &[
        b"the ",
        b"quick ",
        b"brown ",
        b"fox ",
        b"jumps ",
        b"over ",
        b"lazy ",
        b"dog ",
        b"pack ",
        b"my ",
        b"box ",
        b"with ",
        b"five ",
        b"dozen ",
        b"liquor ",
        b"jugs ",
        b"sphinx ",
        b"of ",
        b"black ",
        b"quartz ",
        b"judge ",
        b"how ",
        b"vexingly ",
        b"daft ",
        b"zebras ",
        b"jump ",
        b"a ",
        b"an ",
        b"are ",
        b"as ",
        b"at ",
        b"be ",
    ];
    // Deterministic LCG to pick word indices.
    let mut input = Vec::with_capacity(300 * 1024);
    let mut state: u32 = 0x9E37_79B1;
    while input.len() < 300 * 1024 {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        let idx = (state as usize) % words.len();
        input.extend_from_slice(words[idx]);
    }
    input.truncate(300 * 1024);
    let encoded = zstd_encode(&input);
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_lorem_128k() {
    // 128 KiB exercises multi-block decoding (each block ≤ 128 KiB; this size
    // forces at least 2 blocks at default compression level).
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(128 * 1024);
    while input.len() < 128 * 1024 {
        input.extend_from_slice(snippet);
    }
    input.truncate(128 * 1024);
    let encoded = zstd_encode(&input);
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_mixed_content() {
    // English prose mixed with binary noise — produces a mix of
    // Compressed_Literals and likely some Raw_Block payloads.
    if !tool_available("zstd") {
        return;
    }
    let mut input = Vec::with_capacity(20 * 1024);
    let snippet = b"The quick brown fox jumps over the lazy dog. ";
    let noise = lcg_bytes(0x1234, 4096);
    while input.len() < 20 * 1024 {
        input.extend_from_slice(snippet);
        input.extend_from_slice(&noise[..256]);
    }
    input.truncate(20 * 1024);
    let encoded = zstd_encode(&input);
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_low_level_1() {
    // -1: lowest compression. Often produces simpler block structures.
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"hello, world! ";
    let mut input = Vec::new();
    while input.len() < 4096 {
        input.extend_from_slice(snippet);
    }
    input.truncate(4096);
    use std::io::Write;
    let mut child = std::process::Command::new("zstd")
        .args(["--no-check", "-1", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&input).unwrap();
    let encoded = child.wait_with_output().unwrap().stdout;
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
#[test]
fn decode_zstd_cli_high_compression_level() {
    // Compression level -3 (default), -9 (high), and -1 (low) may produce
    // different block structures (Compressed_Literals_Block vs Treeless,
    // FSE_Compressed_Mode vs Predefined). Test that we handle level 9.
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(8192);
    while input.len() < 8192 {
        input.extend_from_slice(snippet);
    }
    input.truncate(8192);
    use std::io::Write;
    let mut child = std::process::Command::new("zstd")
        .args(["--no-check", "-9", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&input).unwrap();
    let encoded = child.wait_with_output().unwrap().stdout;
    let decoded = decode_all(&encoded);
    assert_eq!(decoded, input);
}

// ─── pseudo-random helper ────────────────────────────────────────────────

fn lcg_bytes(seed: u32, len: usize) -> Vec<u8> {
    // Numerical Recipes LCG. Deterministic, dependency-free, decent for
    // forcing byte-pattern diversity in tests.
    let mut state = seed;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        out.push((state >> 16) as u8);
    }
    out
}

// ─── factory hookup ──────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("zstd").is_some());
        assert!(factory::decoder_by_name("zstd").is_some());
    }

    #[test]
    fn names_contains_zstd() {
        assert!(factory::names().contains(&"zstd"));
    }
}

// ─── encoder: compressed-block emission ────────────────────────────────────

/// Round-trip the new Compressed_Block encoder output through our own decoder.
#[test]
fn encoded_compressed_block_round_trips_through_decoder() {
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(4096);
    while input.len() < 4096 {
        input.extend_from_slice(snippet);
    }
    input.truncate(4096);

    let encoded = encode_chunked(&input, input.len(), input.len() * 2 + 32);
    eprintln!(
        "input {} → encoded {} (ratio {:.2})",
        input.len(),
        encoded.len(),
        encoded.len() as f64 / input.len() as f64
    );
    let decoded = decode_chunked(&encoded, encoded.len(), input.len() * 2);
    assert_eq!(decoded, input);
}

#[cfg(unix)]
fn zstd_decode_external(encoded: &[u8]) -> Result<Vec<u8>, String> {
    use std::io::Write;
    let mut child = std::process::Command::new("zstd")
        .args(["-d", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn zstd: {e}"))?;
    {
        let stdin = child.stdin.as_mut().unwrap();
        stdin
            .write_all(encoded)
            .map_err(|e| format!("write stdin: {e}"))?;
    }
    let out = child.wait_with_output().map_err(|e| format!("wait: {e}"))?;
    if !out.status.success() {
        return Err(format!(
            "zstd -d failed: status {:?} stderr={}",
            out.status,
            String::from_utf8_lossy(&out.stderr)
        ));
    }
    Ok(out.stdout)
}

#[cfg(unix)]
fn cross_validate(input: &[u8]) {
    if !tool_available("zstd") {
        return;
    }
    let encoded = encode_chunked(input, input.len().max(1), input.len().max(64) * 2 + 64);
    // First decode with our own decoder.
    let decoded = decode_chunked(&encoded, encoded.len().max(1), input.len().max(64) * 2 + 64);
    assert_eq!(
        decoded,
        input,
        "own decoder round-trip failed (len={})",
        input.len()
    );
    // Then pipe through system zstd.
    let sys_decoded = zstd_decode_external(&encoded).expect("zstd -d should accept our output");
    assert_eq!(
        sys_decoded,
        input,
        "system zstd -d round-trip mismatch (len={}, encoded={})",
        input.len(),
        encoded.len()
    );
}

#[cfg(unix)]
#[test]
fn cross_validate_empty() {
    cross_validate(&[]);
}

#[cfg(unix)]
#[test]
fn cross_validate_single_byte() {
    cross_validate(b"a");
}

#[cfg(unix)]
#[test]
fn cross_validate_hello() {
    cross_validate(b"hello world\n");
}

#[cfg(unix)]
#[test]
fn cross_validate_lorem_4k() {
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(4096);
    while input.len() < 4096 {
        input.extend_from_slice(snippet);
    }
    input.truncate(4096);
    cross_validate(&input);
}

#[cfg(unix)]
#[test]
fn cross_validate_lorem_16k() {
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(16 * 1024);
    while input.len() < 16 * 1024 {
        input.extend_from_slice(snippet);
    }
    input.truncate(16 * 1024);
    cross_validate(&input);
}

#[cfg(unix)]
#[test]
fn cross_validate_zeros_64k() {
    cross_validate(&vec![0u8; 64 * 1024]);
}

#[cfg(unix)]
#[test]
fn cross_validate_streaming_one_byte() {
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"abc 123 def 456 ghi 789 jkl ";
    let mut input = Vec::with_capacity(2048);
    while input.len() < 2048 {
        input.extend_from_slice(snippet);
    }
    input.truncate(2048);
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
    let sys = zstd_decode_external(&encoded).expect("system zstd accepts streamed output");
    assert_eq!(sys, input);
}

#[cfg(unix)]
#[test]
fn cross_validate_ratio_vs_system_zstd_1() {
    // Rough compression-quality sanity check: our encoder should be at least
    // in the right ballpark compared to system `zstd -1`.
    if !tool_available("zstd") {
        return;
    }
    let snippet = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut input = Vec::with_capacity(8192);
    while input.len() < 8192 {
        input.extend_from_slice(snippet);
    }
    input.truncate(8192);

    let our_encoded = encode_chunked(&input, input.len(), input.len() * 2 + 64);
    // Compare to system zstd -1.
    use std::io::Write;
    let mut child = std::process::Command::new("zstd")
        .args(["--no-check", "-1", "-c"])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.as_mut().unwrap().write_all(&input).unwrap();
    let sys_encoded = child.wait_with_output().unwrap().stdout;

    eprintln!(
        "input {} bytes; ours {} (ratio {:.3}); system zstd -1 {} (ratio {:.3})",
        input.len(),
        our_encoded.len(),
        our_encoded.len() as f64 / input.len() as f64,
        sys_encoded.len(),
        sys_encoded.len() as f64 / input.len() as f64
    );
    // Sanity floor: our output should be < input.len() (real compression).
    assert!(
        our_encoded.len() < input.len(),
        "encoder produced larger output than input"
    );
}

#[cfg(unix)]
#[test]
fn measure_compression_ratios() {
    // Informational: print the sizes our encoder produces for various inputs
    // and compare against the system zstd at -1 and -3. This is a diagnostic,
    // not a pass/fail test (we just check the output decodes).
    if !tool_available("zstd") {
        return;
    }
    let snippet_lorem = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let make_lorem = |n: usize| {
        let mut v = Vec::with_capacity(n);
        while v.len() < n {
            v.extend_from_slice(snippet_lorem);
        }
        v.truncate(n);
        v
    };

    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("lorem-1k", make_lorem(1024)),
        ("lorem-4k", make_lorem(4096)),
        ("lorem-16k", make_lorem(16 * 1024)),
        ("zeros-64k", vec![0u8; 64 * 1024]),
        ("repeat-a-50k", vec![b'a'; 50 * 1024]),
    ];

    use std::io::Write;
    for (name, input) in &cases {
        let ours = encode_chunked(input, input.len(), input.len() * 2 + 64);
        // system zstd -1
        let mut child = std::process::Command::new("zstd")
            .args(["--no-check", "-1", "-c"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(input).unwrap();
        let sys1 = child.wait_with_output().unwrap().stdout;
        // system zstd -3 (default)
        let mut child = std::process::Command::new("zstd")
            .args(["--no-check", "-3", "-c"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .spawn()
            .unwrap();
        child.stdin.as_mut().unwrap().write_all(input).unwrap();
        let sys3 = child.wait_with_output().unwrap().stdout;
        eprintln!(
            "{:14} input={:7}  ours={:6} ({:.3})  zstd-1={:6} ({:.3})  zstd-3={:6} ({:.3})",
            name,
            input.len(),
            ours.len(),
            ours.len() as f64 / input.len() as f64,
            sys1.len(),
            sys1.len() as f64 / input.len() as f64,
            sys3.len(),
            sys3.len() as f64 / input.len() as f64
        );
    }
}
