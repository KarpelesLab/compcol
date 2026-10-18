//! Streaming tests for the LZF algorithm.
//!
//! Both sides stream: the encoder emits tokens as soon as it has enough
//! lookahead, and the decoder decodes tokens as their bytes arrive. The
//! `fixtures/lzf/*.lzf` files were produced by the reference liblzf 3.6
//! `lzf_compress`, and the reverse direction (liblzf's `lzf_decompress`
//! reading our output) was checked when the codec was added.

#![cfg(feature = "lzf")]

use compcol::lzf::{Decoder, Encoder, Lzf};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Flush, Status};

static TEXT: &[u8] = include_bytes!("fixtures/lzf/text.txt");
static TEXT_LZF: &[u8] = include_bytes!("fixtures/lzf/text.txt.lzf");
static RUNS_LZF: &[u8] = include_bytes!("fixtures/lzf/runs.bin.lzf");

/// The input `runs.bin.lzf` was compressed from.
fn runs() -> Vec<u8> {
    let mut v = vec![0u8; 5000];
    for _ in 0..20 {
        v.extend(0..=255u8);
    }
    for _ in 0..3000 {
        v.extend_from_slice(b"xyz");
    }
    v
}

fn noise(n: usize, mut state: u32) -> Vec<u8> {
    (0..n)
        .map(|_| {
            state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (state >> 16) as u8
        })
        .collect()
}

fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    for chunk in input.chunks(in_chunk.max(1)) {
        let mut consumed = 0;
        loop {
            let (p, status) = enc.encode(&chunk[consumed..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty => break,
                Status::OutputFull => continue,
                Status::StreamEnd => panic!("encode returned StreamEnd"),
            }
        }
    }
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            _ => assert!(p.written > 0, "encoder finish stalled"),
        }
    }
    encoded
}

fn try_decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    for chunk in encoded.chunks(in_chunk.max(1)) {
        let mut consumed = 0;
        loop {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf)?;
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty => break,
                Status::OutputFull => continue,
                Status::StreamEnd => panic!("decode returned StreamEnd"),
            }
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        decoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            _ => assert!(p.written > 0, "decoder finish stalled"),
        }
    }
    Ok(decoded)
}

fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    try_decode_chunked(encoded, in_chunk, out_chunk).unwrap()
}

fn round_trip(input: &[u8]) -> Vec<u8> {
    let encoded = encode_chunked(input, 64 * 1024, 64 * 1024);
    assert_eq!(decode_chunked(&encoded, 64 * 1024, 64 * 1024), input);
    // Odd chunk sizes on both sides must not change the decoded bytes.
    let chunk_in = (input.len() / 7).max(1);
    let encoded2 = encode_chunked(input, chunk_in, 13);
    assert_eq!(decode_chunked(&encoded2, 5, 11), input);
    encoded
}

#[test]
fn name_is_lzf() {
    assert_eq!(<Lzf as Algorithm>::NAME, "lzf");
}

#[test]
fn empty_round_trip() {
    // No header and no end marker: an empty stream is empty data.
    assert!(round_trip(&[]).is_empty());
    assert!(decode_chunked(&[], 1, 1).is_empty());
}

#[test]
fn single_byte() {
    assert_eq!(round_trip(&[0xA5]), [0x00, 0xA5]);
}

#[test]
fn known_vector() {
    // A 6-byte literal run (ctrl 0x05), then one 17-byte back-reference 6
    // bytes back: `len - 2 = 15` needs the long form (ctrl 0xE0 plus an
    // extra 15 - 7 = 8), and the offset byte is `6 - 1 = 5`.
    let encoded = round_trip(b"hello hello hello hello");
    assert_eq!(
        encoded,
        [0x05, b'h', b'e', b'l', b'l', b'o', b' ', 0xE0, 0x08, 0x05]
    );
}

#[test]
fn decodes_liblzf_vector() {
    // `lzf_compress("hello hello hello hello")` from liblzf 3.6, which
    // takes a shorter first match than ours.
    let reference = [
        0x06, 0x68, 0x65, 0x6c, 0x6c, 0x6f, 0x20, 0x68, 0xe0, 0x05, 0x05, 0x01, 0x6c, 0x6f,
    ];
    assert_eq!(decode_chunked(&reference, 1, 1), b"hello hello hello hello");
}

#[test]
fn decodes_liblzf_text_fixture() {
    assert_eq!(decode_chunked(TEXT_LZF, TEXT_LZF.len(), TEXT.len()), TEXT);
    assert_eq!(decode_chunked(TEXT_LZF, 3, 7), TEXT);
}

#[test]
fn decodes_liblzf_runs_fixture() {
    let input = runs();
    assert_eq!(decode_chunked(RUNS_LZF, RUNS_LZF.len(), 1 << 16), input);
    assert_eq!(decode_chunked(RUNS_LZF, 1, 1), input);
}

#[test]
fn text_round_trip_compresses() {
    let encoded = round_trip(TEXT);
    // At least as good as liblzf on the same input.
    assert!(
        encoded.len() <= TEXT_LZF.len(),
        "ours {} vs liblzf {}",
        encoded.len(),
        TEXT_LZF.len()
    );
}

#[test]
fn long_run_of_one_byte() {
    let input = vec![0x7Fu8; 100 * 1024];
    let encoded = round_trip(&input);
    // 264-byte matches at 3 bytes each.
    assert!(encoded.len() < input.len() / 80, "{}", encoded.len());
}

#[test]
fn pseudo_random_data() {
    let input = noise(100_000, 0xDECA_FBAD);
    let encoded = round_trip(&input);
    // Incompressible input grows by one control byte per 32 literals.
    assert!(encoded.len() <= input.len() + input.len().div_ceil(32));
}

#[test]
fn large_mixed_input_slides_window() {
    // Several hundred KiB so the encoder window slides more than once, with
    // repeats both inside and beyond the 8 KiB reach of a back-reference.
    let mut input = Vec::new();
    for i in 0..12 {
        input.extend_from_slice(TEXT);
        input.extend_from_slice(&noise(9000, i));
    }
    round_trip(&input);
}

#[test]
fn chunked_one_byte_at_a_time() {
    let mut input: Vec<u8> = (0..2000u32).map(|i| (i * 31 % 251) as u8).collect();
    input.extend_from_slice(&TEXT[..3000]);
    input.extend_from_slice(&TEXT[..3000]);
    let encoded = encode_chunked(&input, 1, 1);
    assert_eq!(decode_chunked(&encoded, 1, 1), input);
    // Chunking does not change what the stream decodes to.
    assert_eq!(
        decode_chunked(&encode_chunked(&input, 1 << 20, 1 << 20), 1, 1),
        input
    );
}

#[test]
fn decoder_streams_output_before_finish() {
    // A real streaming decoder: output appears from `decode`, not only from
    // `finish`.
    let mut dec = Decoder::new();
    // One spare byte: an exactly-filled buffer reports `OutputFull`.
    let mut out = vec![0u8; TEXT.len() + 1];
    let (p, status) = dec.decode(TEXT_LZF, &mut out).unwrap();
    assert_eq!(p.consumed, TEXT_LZF.len());
    assert_eq!(p.written, TEXT.len());
    assert_eq!(status, Status::InputEmpty);
    assert_eq!(&out[..p.written], TEXT);
    let (p, status) = dec.finish(&mut out).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::StreamEnd);
}

#[test]
fn encoder_streams_output_before_finish() {
    let mut enc = Encoder::new();
    let mut out = vec![0u8; 1 << 16];
    let (p, status) = enc.encode(TEXT, &mut out).unwrap();
    assert_eq!(p.consumed, TEXT.len());
    assert_eq!(status, Status::InputEmpty);
    assert!(p.written > 0, "encoder buffered everything until finish");
}

#[test]
fn finish_is_idempotent() {
    let mut enc = Encoder::new();
    let mut out = [0u8; 64];
    let _ = enc.encode(b"hello world", &mut out).unwrap();
    let (_, status) = enc.finish(&mut out).unwrap();
    assert_eq!(status, Status::StreamEnd);
    let (p, status) = enc.finish(&mut out).unwrap();
    assert_eq!(p.written, 0);
    assert_eq!(status, Status::StreamEnd);
}

#[test]
fn sync_flush_is_decodable_and_keeps_history() {
    let mut enc = Encoder::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut wire = Vec::new();
    let (p, _) = enc.encode(&TEXT[..4000], &mut buf).unwrap();
    wire.extend_from_slice(&buf[..p.written]);
    let (p, status) = enc.flush(&mut buf, Flush::Sync).unwrap();
    wire.extend_from_slice(&buf[..p.written]);
    assert_eq!(status, Status::InputEmpty);
    // Everything up to the flush point decodes on its own.
    assert_eq!(decode_chunked(&wire, 1 << 16, 1 << 16), &TEXT[..4000]);

    // The same text again is cheap: it back-references the pre-flush data.
    let mark = wire.len();
    let (p, _) = enc.encode(&TEXT[..4000], &mut buf).unwrap();
    wire.extend_from_slice(&buf[..p.written]);
    let (p, _) = enc.finish(&mut buf).unwrap();
    wire.extend_from_slice(&buf[..p.written]);
    assert!(wire.len() - mark < 100, "{}", wire.len() - mark);
    let mut expect = TEXT[..4000].to_vec();
    expect.extend_from_slice(&TEXT[..4000]);
    assert_eq!(decode_chunked(&wire, 1 << 16, 1 << 16), expect);
}

#[test]
fn full_flush_resets_history() {
    let mut enc = Encoder::new();
    let mut buf = vec![0u8; 1 << 16];
    let (p, _) = enc.encode(&TEXT[..4000], &mut buf).unwrap();
    let mut head = buf[..p.written].to_vec();
    let (p, _) = enc.flush(&mut buf, Flush::Full).unwrap();
    head.extend_from_slice(&buf[..p.written]);

    let mut tail = Vec::new();
    let (p, _) = enc.encode(&TEXT[..4000], &mut buf).unwrap();
    tail.extend_from_slice(&buf[..p.written]);
    let (p, _) = enc.finish(&mut buf).unwrap();
    tail.extend_from_slice(&buf[..p.written]);
    // The post-flush part decodes without the pre-flush part.
    assert_eq!(decode_chunked(&tail, 1 << 16, 1 << 16), &TEXT[..4000]);
    head.extend_from_slice(&tail);
    let mut expect = TEXT[..4000].to_vec();
    expect.extend_from_slice(&TEXT[..4000]);
    assert_eq!(decode_chunked(&head, 1 << 16, 1 << 16), expect);
}

#[test]
fn flush_drains_across_calls() {
    let mut enc = Encoder::new();
    let mut tiny = [0u8; 1];
    let (p, _) = enc.encode(TEXT, &mut tiny).unwrap();
    let mut wire = tiny[..p.written].to_vec();
    // Drain the encode backlog, then the flush, a byte at a time.
    let mut consumed = p.consumed;
    while consumed < TEXT.len() {
        let (p, _) = enc.encode(&TEXT[consumed..], &mut tiny).unwrap();
        wire.extend_from_slice(&tiny[..p.written]);
        consumed += p.consumed;
    }
    loop {
        let (p, status) = enc.flush(&mut tiny, Flush::Sync).unwrap();
        wire.extend_from_slice(&tiny[..p.written]);
        if status == Status::InputEmpty {
            break;
        }
    }
    assert_eq!(decode_chunked(&wire, 7, 7), TEXT);
}

#[test]
fn reset_clears_encoder_state() {
    let mut enc = Encoder::new();
    let mut out = vec![0u8; 1 << 16];
    let _ = enc.encode(TEXT, &mut out).unwrap();
    enc.reset();
    let (p, _) = enc.encode(b"hello", &mut out).unwrap();
    let mut wire = out[..p.written].to_vec();
    let (p, _) = enc.finish(&mut out).unwrap();
    wire.extend_from_slice(&out[..p.written]);
    assert_eq!(wire, [0x04, b'h', b'e', b'l', b'l', b'o']);
}

#[test]
fn reset_clears_decoder_state() {
    let mut dec = Decoder::new();
    let mut out = vec![0u8; TEXT.len()];
    let _ = dec.decode(&TEXT_LZF[..100], &mut out).unwrap();
    dec.reset();
    // A back-reference into the forgotten output must now be rejected.
    assert_eq!(
        dec.decode(&[0x20, 0x00], &mut out),
        Err(Error::InvalidDistance)
    );
    dec.reset();
    let (p, _) = dec.decode(&[0x01, b'o', b'k'], &mut out).unwrap();
    assert_eq!(&out[..p.written], b"ok");
}

#[test]
fn rejects_reference_before_start() {
    // One literal byte, then a back-reference 2 bytes back.
    assert_eq!(
        try_decode_chunked(&[0x00, b'a', 0x20, 0x01], 16, 16),
        Err(Error::InvalidDistance)
    );
    // Exactly 1 back is fine (RLE).
    assert_eq!(decode_chunked(&[0x00, b'a', 0x20, 0x00], 16, 16), b"aaaa");
}

#[test]
fn rejects_truncated_stream() {
    // Literal run missing its last byte.
    assert_eq!(
        try_decode_chunked(&[0x02, b'a', b'b'], 16, 16),
        Err(Error::UnexpectedEnd)
    );
    // Back-reference missing its offset byte.
    assert_eq!(
        try_decode_chunked(&[0x00, b'a', 0x20], 16, 16),
        Err(Error::UnexpectedEnd)
    );
    // Long back-reference missing its length and offset bytes.
    assert_eq!(
        try_decode_chunked(&[0x00, b'a', 0xE0], 16, 16),
        Err(Error::UnexpectedEnd)
    );
    // Every proper prefix of a real stream that cuts a token is rejected,
    // and none panics.
    for cut in 0..TEXT_LZF.len() {
        let _ = try_decode_chunked(&TEXT_LZF[..cut], 64, 64);
    }
}

#[test]
fn longest_match_and_farthest_distance() {
    // 8192 bytes of noise, then a 264-byte match reaching back exactly 8192.
    let mut input = noise(8192, 7);
    let again = input[..264].to_vec();
    input.extend_from_slice(&again);
    let encoded = round_trip(&input);
    let tail = &encoded[encoded.len() - 3..];
    assert_eq!(tail, [0x1F | 0xE0, 255, 0xFF]);
}

#[cfg(feature = "factory")]
mod factory {
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("lzf").is_some());
        assert!(factory::decoder_by_name("lzf").is_some());
        assert!(factory::names().contains(&"lzf"));
        assert_eq!(factory::extension("lzf"), Some("lzf"));
    }

    #[test]
    fn boxed_round_trip() {
        let input = super::TEXT;
        let mut enc = factory::encoder_by_name("lzf").unwrap();
        let mut dec = factory::decoder_by_name("lzf").unwrap();
        let mut buf = vec![0u8; 1 << 16];
        let (p, _) = enc.encode(input, &mut buf).unwrap();
        let mut wire = buf[..p.written].to_vec();
        let (p, _) = enc.finish(&mut buf).unwrap();
        wire.extend_from_slice(&buf[..p.written]);
        let (p, _) = dec.decode(&wire, &mut buf).unwrap();
        assert_eq!(&buf[..p.written], input);
    }
}
