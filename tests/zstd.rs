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
        if p.done {
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
        if p.done {
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
        if pf.done {
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
        if pdf.done {
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
        if pf.done {
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
        if pf.done {
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
        if pf.done {
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
        if pf.done {
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
        if pf.done {
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
fn decode_returns_unsupported_for_compressed_block() {
    // Build a frame announcing a Compressed_Block (Type=2). The decoder
    // should refuse with Unsupported before it tries to parse the payload.
    let mut f = Vec::new();
    f.extend_from_slice(&[0x28, 0xB5, 0x2F, 0xFD]);
    f.push(0x00);
    f.push(0x50);
    // BH: Last=1, Type=2 (Compressed), Size=2 (arbitrary).
    let bh: u32 = 1 | (2u32 << 1) | (2u32 << 3);
    f.push((bh & 0xFF) as u8);
    f.push(((bh >> 8) & 0xFF) as u8);
    f.push(((bh >> 16) & 0xFF) as u8);
    f.push(0x00);
    f.push(0x00);
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let err = dec.decode(&f, &mut out).unwrap_err();
    assert_eq!(err, Error::Unsupported);
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
        if pf.done {
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
fn decode_known_good_zstd_fixture_compressed_unsupported() {
    // The classic case: data large enough that `zstd -1` actually emits a
    // Compressed_Block. We can't easily inline a real fixture here without
    // regenerating against a known-stable zstd version, so we build a frame
    // by hand whose body is a Compressed_Block (Type=2). The decoder must
    // reject it as Unsupported.
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
    assert_eq!(err, Error::Unsupported);
}

// ─── encoder: frame shape sanity ─────────────────────────────────────────

#[test]
fn encoder_emits_valid_frame_header() {
    let encoded = encode_chunked(b"x", 16, 16);
    // First 4 bytes are the magic.
    assert_eq!(&encoded[..4], &[0x28, 0xB5, 0x2F, 0xFD]);
    // FHD should be 0x00 (see module docs).
    assert_eq!(encoded[4], 0x00);
    // WD = 0x50 (Exp=10, Mant=0).
    assert_eq!(encoded[5], 0x50);
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
    assert_eq!(encoded[5], 0x50);
    // 3-byte block header with Last=1, Type=0, Size=0 → bytes 01 00 00.
    assert_eq!(&encoded[6..9], &[0x01, 0x00, 0x00]);
    assert_eq!(encoded.len(), 9);
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
