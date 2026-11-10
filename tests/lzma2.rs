//! Public-API tests for the raw LZMA2 codec (7-Zip coder id 21).
//!
//! The in-module unit tests (`src/lzma2/mod.rs`) cover encoder/decoder
//! round-trips, dict resets, fallback, and 1-byte streaming. Here we
//! validate the public surface: encoder→decoder round-trips through the
//! `Lzma2` public types, decoding hand-framed *uncompressed* LZMA2 chunks,
//! self-termination on the `0x00` control byte, cross-validation against the
//! shared `xz` chunk codec, the factory wiring, and DoS hygiene on crafted
//! input.

#![cfg(feature = "lzma2")]

use compcol::lzma2::{DecoderConfig, Lzma2};
#[allow(unused_imports)]
use compcol::{Algorithm, ContiguousDecoder, Decoder, Encoder, Error, Flush, Status};

/// Frame `data` as a single uncompressed dict-reset chunk (control 0x01)
/// followed by the 0x00 end marker. Uncompressed chunks carry the bytes
/// verbatim, so no encoder is needed to build a valid raw LZMA2 stream.
fn uncompressed_stream(data: &[u8]) -> Vec<u8> {
    assert!(!data.is_empty() && data.len() <= 1 << 16);
    let m1 = (data.len() - 1) as u16;
    let mut s = Vec::new();
    s.push(0x01);
    s.push((m1 >> 8) as u8);
    s.push((m1 & 0xFF) as u8);
    s.extend_from_slice(data);
    s.push(0x00);
    s
}

/// Decode `stream` with the streaming calls — and check that the
/// contiguous ones agree (see `assert_contiguous_agrees`), so that every
/// test going through here covers both modes.
fn decode_all(stream: &[u8], cfg: DecoderConfig, out_cap: usize) -> Result<Vec<u8>, Error> {
    let result = decode_all_streaming(stream, cfg, out_cap);
    assert_contiguous_agrees(stream, cfg, &result);
    result
}

fn decode_all_streaming(
    stream: &[u8],
    cfg: DecoderConfig,
    out_cap: usize,
) -> Result<Vec<u8>, Error> {
    let mut dec = Lzma2::decoder_with(cfg);
    let mut out = vec![0u8; out_cap + 16];
    let mut consumed = 0;
    let mut written = 0;
    loop {
        let (p, st) = dec.decode(&stream[consumed..], &mut out[written..])?;
        consumed += p.consumed;
        written += p.written;
        match st {
            Status::StreamEnd => break,
            Status::InputEmpty if consumed >= stream.len() => {
                dec.finish(&mut out[written..])?;
                break;
            }
            _ => {}
        }
    }
    out.truncate(written);
    Ok(out)
}

#[test]
fn uncompressed_chunk_roundtrip() {
    let data: Vec<u8> = (0u8..=255).cycle().take(5000).collect();
    let stream = uncompressed_stream(&data);
    let got = decode_all(&stream, DecoderConfig::default(), data.len()).unwrap();
    assert_eq!(got, data);
}

#[test]
fn one_byte_streaming() {
    let data = b"streamed one byte at a time through every phase boundary".to_vec();
    let stream = uncompressed_stream(&data);
    let mut dec = Lzma2::decoder_with(DecoderConfig::default());
    let mut produced = Vec::new();
    let mut i = 0;
    let mut ob = [0u8; 1];
    loop {
        let inb = if i < stream.len() {
            &stream[i..i + 1]
        } else {
            &[][..]
        };
        let (p, st) = dec.decode(inb, &mut ob).unwrap();
        i += p.consumed;
        if p.written == 1 {
            produced.push(ob[0]);
        }
        if st == Status::StreamEnd {
            break;
        }
        assert!(
            !(p.consumed == 0 && p.written == 0 && i >= stream.len()),
            "stalled"
        );
    }
    assert_eq!(produced, data);
}

#[test]
fn empty_stream_is_just_end_marker() {
    let got = decode_all(&[0x00], DecoderConfig::default(), 0).unwrap();
    assert!(got.is_empty());
}

#[test]
fn truncated_stream_errors() {
    // Uncompressed chunk header promises 10 bytes but the stream is clipped.
    let stream = vec![0x01u8, 0x00, 0x09, 1, 2, 3];
    let mut dec = Lzma2::decoder_with(DecoderConfig::default());
    let mut out = [0u8; 32];
    let (_p, st) = dec.decode(&stream, &mut out).unwrap();
    assert_ne!(st, Status::StreamEnd);
    // No more input, no end marker → finish reports truncation.
    assert_eq!(dec.finish(&mut out), Err(Error::UnexpectedEnd));
}

#[test]
fn corrupt_control_rejected() {
    let mut dec = Lzma2::decoder_with(DecoderConfig::default());
    let mut out = [0u8; 16];
    // 0x7F is an invalid control byte.
    assert_eq!(dec.decode(&[0x7F], &mut out), Err(Error::Corrupt));
}

#[test]
fn invalid_dict_prop_poisons() {
    let mut dec = Lzma2::decoder_with(DecoderConfig::with_dict_prop(200));
    let mut out = [0u8; 16];
    assert_eq!(dec.decode(&[0x00], &mut out), Err(Error::Corrupt));
}

#[test]
#[cfg(feature = "factory")]
fn factory_wiring() {
    assert!(compcol::factory::names().contains(&"lzma2"));
    assert_eq!(compcol::factory::extension("lzma2"), Some("lzma2"));
    assert!(compcol::factory::decoder_by_name("lzma2").is_some());
    // The encoder is now a real working encoder: a factory-built encoder
    // round-trips through a factory-built decoder.
    let data = b"factory-routed lzma2 round-trip round-trip round-trip";
    let mut enc = compcol::factory::encoder_by_name("lzma2").expect("encoder present");
    let mut stream = Vec::new();
    let mut obuf = [0u8; 256];
    let (p, _) = enc.encode(data, &mut obuf).unwrap();
    stream.extend_from_slice(&obuf[..p.written]);
    loop {
        let (p, st) = enc.finish(&mut obuf).unwrap();
        stream.extend_from_slice(&obuf[..p.written]);
        if st == Status::StreamEnd {
            break;
        }
    }
    let got = decode_all(&stream, DecoderConfig::default(), data.len()).unwrap();
    assert_eq!(got, data);
}

/// Encode `data` with the public raw LZMA2 [`Lzma2`] encoder, draining
/// `output` in `out_chunk`-sized slices to exercise the streaming API.
fn encode_all(data: &[u8], out_chunk: usize) -> Vec<u8> {
    let mut enc = Lzma2::encoder_with(());
    let mut stream = Vec::new();
    let mut obuf = vec![0u8; out_chunk];
    let mut consumed = 0;
    loop {
        let (p, st) = enc.encode(&data[consumed..], &mut obuf).unwrap();
        stream.extend_from_slice(&obuf[..p.written]);
        consumed += p.consumed;
        match st {
            Status::InputEmpty => break,
            Status::OutputFull => {}
            Status::StreamEnd => unreachable!(),
        }
    }
    loop {
        let (p, st) = enc.finish(&mut obuf).unwrap();
        stream.extend_from_slice(&obuf[..p.written]);
        if st == Status::StreamEnd {
            break;
        }
    }
    stream
}

#[test]
fn encoder_decoder_roundtrip_public() {
    // Cover the required spread of input shapes through the public API.
    let zeros = vec![0u8; 130 * 1024];
    let big: Vec<u8> = (0u32..150_000)
        .map(|i| (i.wrapping_mul(2654435761) >> 19) as u8)
        .collect();
    let mut rnd = vec![0u8; 8192];
    let mut x = 0x9e37_79b9u32;
    for b in rnd.iter_mut() {
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        *b = (x >> 24) as u8;
    }
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"q".to_vec(),
        b"the quick brown fox jumps over the lazy dog".to_vec(),
        zeros,
        big,
        rnd,
    ];
    for data in &cases {
        for out_chunk in [7usize, 1 << 16] {
            let stream = encode_all(data, out_chunk);
            let got = decode_all(&stream, DecoderConfig::default(), data.len()).unwrap();
            assert_eq!(&got, data, "len={} out_chunk={out_chunk}", data.len());
        }
    }
}

/// Cross-validate framing against the shared `xz` chunk codec: wrap the raw
/// LZMA2 stream this encoder emits inside a minimal `.xz` container and decode
/// it with the public `xz` decoder. Because the `xz` and `lzma2` paths share
/// `lzma2_decoder`, a successful decode proves our chunk framing is exactly
/// what `xz` consumes. We build the container around our own payload rather
/// than re-encoding with `xz`, so this exercises *our* bytes.
#[test]
#[cfg(feature = "xz")]
fn xz_cross_validates_framing() {
    use compcol::xz::Xz;

    fn crc32(data: &[u8]) -> u32 {
        let mut s = 0xFFFF_FFFFu32;
        for &b in data {
            s ^= b as u32;
            for _ in 0..8 {
                s = if s & 1 != 0 {
                    0xEDB8_8320 ^ (s >> 1)
                } else {
                    s >> 1
                };
            }
        }
        s ^ 0xFFFF_FFFF
    }
    fn varint(mut v: u64, out: &mut Vec<u8>) {
        while v >= 0x80 {
            out.push((v as u8 & 0x7F) | 0x80);
            v >>= 7;
        }
        out.push(v as u8);
    }

    // Data with both compressible and incompressible regions so the payload
    // contains compressed (0xE0) and uncompressed (0x01) chunks.
    let mut data = vec![0u8; 100 * 1024];
    let mut x = 0x1234_5678u32;
    for (i, b) in data.iter_mut().enumerate() {
        if i % 3 == 0 {
            *b = 0; // compressible runs
        } else {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            *b = (x >> 24) as u8;
        }
    }

    // Our raw LZMA2 payload (chunks + 0x00 end marker), unchanged.
    let payload = encode_all(&data, 1 << 16);

    // ── Stream Header: magic | flags(00,01=CRC32) | CRC32(flags) ──
    let mut xz = vec![0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x01];
    xz.extend_from_slice(&crc32(&[0x00, 0x01]).to_le_bytes());

    // ── Block Header: size byte | flags | filter id | props size | dict
    //    flag (0x14 = 4 MiB) | pad to mult-of-4-minus-CRC | CRC32 ──
    let mut bh = vec![0x02u8, 0x00, 0x21, 0x01, 0x14, 0x00, 0x00, 0x00];
    let bh_crc = crc32(&bh).to_le_bytes();
    bh.extend_from_slice(&bh_crc);
    let block_header_len = bh.len() as u64;
    xz.extend_from_slice(&bh);

    // ── Block payload + padding + Check(CRC32 of uncompressed data) ──
    xz.extend_from_slice(&payload);
    let compressed_size = payload.len() as u64;
    let unpadded_no_pad = block_header_len + compressed_size + 4;
    let pad = ((4 - (unpadded_no_pad % 4)) % 4) as usize;
    xz.extend(core::iter::repeat_n(0u8, pad));
    xz.extend_from_slice(&crc32(&data).to_le_bytes());

    // ── Index: 00 | numrec | (unpadded, uncompressed) | pad | CRC32 ──
    let unpadded_size = block_header_len + compressed_size + 4;
    let mut idx = vec![0x00u8];
    varint(1, &mut idx);
    varint(unpadded_size, &mut idx);
    varint(data.len() as u64, &mut idx);
    while idx.len() % 4 != 0 {
        idx.push(0x00);
    }
    let idx_crc = crc32(&idx).to_le_bytes();
    idx.extend_from_slice(&idx_crc);
    let index_size = idx.len() as u32;
    xz.extend_from_slice(&idx);

    // ── Stream Footer: CRC32(body) | backward_size | flags | magic ──
    let mut footer_body = ((index_size / 4) - 1).to_le_bytes().to_vec();
    footer_body.push(0x00);
    footer_body.push(0x01);
    let f_crc = crc32(&footer_body).to_le_bytes();
    xz.extend_from_slice(&f_crc);
    xz.extend_from_slice(&footer_body);
    xz.extend_from_slice(&[0x59, 0x5A]);

    // Decode the whole thing through the public xz decoder.
    let mut dec = Xz::decoder_with(());
    let mut out = vec![0u8; data.len() + 64];
    let mut consumed = 0;
    let mut written = 0;
    loop {
        let (p, st) = dec.decode(&xz[consumed..], &mut out[written..]).unwrap();
        consumed += p.consumed;
        written += p.written;
        match st {
            Status::StreamEnd => break,
            Status::InputEmpty if consumed >= xz.len() => {
                // Whole container consumed; finish surfaces the trailer end.
                let (p, fst) = dec.finish(&mut out[written..]).unwrap();
                written += p.written;
                assert_eq!(fst, Status::StreamEnd, "xz trailer not terminated");
                break;
            }
            _ => assert!(
                !(p.consumed == 0 && p.written == 0),
                "xz decoder stalled — framing mismatch"
            ),
        }
    }
    out.truncate(written);
    assert_eq!(
        out, data,
        "xz cross-decode of our raw LZMA2 framing mismatched"
    );
}

// ─── flush ──────────────────────────────────────────────────────────────

/// Feed all of `input` through `enc.encode`, draining via `out_chunk`-byte
/// buffers, and append what it emits to `wire`.
fn flush_test_encode(enc: &mut Lzma2Encoder, input: &[u8], out_chunk: usize, wire: &mut Vec<u8>) {
    let mut buf = vec![0u8; out_chunk];
    let mut consumed = 0;
    loop {
        let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
        wire.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::InputEmpty if consumed == input.len() => break,
            Status::InputEmpty | Status::OutputFull => {}
            Status::StreamEnd => panic!("encode returned StreamEnd"),
        }
    }
}

/// Drive `enc.flush(mode)` until it reports `InputEmpty`, re-calling on
/// `OutputFull` as the trait requires.
fn flush_test_flush(enc: &mut Lzma2Encoder, mode: Flush, out_chunk: usize, wire: &mut Vec<u8>) {
    let mut buf = vec![0u8; out_chunk];
    for _ in 0..10_000_000 {
        let (p, status) = enc.flush(&mut buf, mode).unwrap();
        wire.extend_from_slice(&buf[..p.written]);
        match status {
            Status::InputEmpty => return,
            Status::OutputFull => {}
            Status::StreamEnd => panic!("flush returned StreamEnd"),
        }
    }
    panic!("flush never completed");
}

fn flush_test_finish(enc: &mut Lzma2Encoder, out_chunk: usize, wire: &mut Vec<u8>) {
    let mut buf = vec![0u8; out_chunk];
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        wire.extend_from_slice(&buf[..p.written]);
        if status == Status::StreamEnd {
            return;
        }
    }
}

/// Decode a stream cut short at a flush point: `decode` only, never
/// `finish` (the stream is deliberately unterminated).
fn decode_prefix(wire: &[u8]) -> Vec<u8> {
    let mut dec = Lzma2::decoder();
    let mut out = Vec::new();
    let mut buf = vec![0u8; 1 << 16];
    let mut consumed = 0;
    loop {
        let (p, _) = dec.decode(&wire[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if p.consumed == 0 && p.written == 0 {
            return out;
        }
    }
}

/// Encode `flush_segments()` with a `mode` flush after each, checking after
/// every flush that the bytes emitted so far decode to everything given so
/// far. Returns the finished stream and the concatenated input.
fn flush_after_each_segment(mode: Flush, out_chunk: usize) -> (Vec<u8>, Vec<u8>) {
    let mut enc = Lzma2::encoder();
    let mut wire = Vec::new();
    let mut given = Vec::new();
    for seg in flush_segments() {
        flush_test_encode(&mut enc, &seg, out_chunk, &mut wire);
        given.extend_from_slice(&seg);
        flush_test_flush(&mut enc, mode, out_chunk, &mut wire);
        let got = decode_prefix(&wire);
        assert!(
            got == given,
            "{mode:?} flush after {} bytes: decoded {} bytes from the prefix",
            given.len(),
            got.len()
        );
        // A second flush with nothing new pending emits nothing.
        let before = wire.len();
        flush_test_flush(&mut enc, mode, out_chunk, &mut wire);
        assert_eq!(wire.len(), before, "empty {mode:?} flush emitted bytes");
    }
    flush_test_finish(&mut enc, out_chunk, &mut wire);
    assert_eq!(
        decode_all(&wire, DecoderConfig::default(), given.len()).unwrap(),
        given
    );
    (wire, given)
}

#[test]
fn sync_flush_makes_everything_given_decodable() {
    flush_after_each_segment(Flush::Sync, 4096);
}

#[test]
fn full_flush_makes_everything_given_decodable() {
    flush_after_each_segment(Flush::Full, 4096);
}

#[test]
fn flush_with_one_byte_output_buffer() {
    flush_after_each_segment(Flush::Sync, 1);
    flush_after_each_segment(Flush::Full, 1);
}

/// After a `Sync` flush, repeated data back-references the pre-flush bytes
/// and costs almost nothing; after a `Full` flush it must be encoded from
/// scratch.
#[test]
fn full_flush_drops_history_sync_keeps_it() {
    let text = flush_text(20_000);
    let tail_size = |mode: Flush| {
        let mut enc = Lzma2::encoder();
        let mut wire = Vec::new();
        flush_test_encode(&mut enc, &text, 4096, &mut wire);
        flush_test_flush(&mut enc, mode, 4096, &mut wire);
        let mark = wire.len();
        flush_test_encode(&mut enc, &text, 4096, &mut wire);
        flush_test_flush(&mut enc, Flush::Sync, 4096, &mut wire);
        let tail = wire.len() - mark;
        flush_test_finish(&mut enc, 4096, &mut wire);
        let mut expect = text.clone();
        expect.extend_from_slice(&text);
        assert_eq!(
            decode_all(&wire, DecoderConfig::default(), expect.len()).unwrap(),
            expect
        );
        tail
    };
    let sync_tail = tail_size(Flush::Sync);
    let full_tail = tail_size(Flush::Full);
    assert!(sync_tail < 100, "sync tail {sync_tail} bytes");
    assert!(
        full_tail > 10 * sync_tail,
        "full tail {full_tail} bytes vs sync tail {sync_tail}"
    );
}

/// Run `cmd args` with `stdin_data` on stdin; returns its output whatever
/// the exit status.
fn run_tool(cmd: &str, args: &[&str], stdin_data: &[u8]) -> std::process::Output {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut child = Command::new(cmd)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let data = stdin_data.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&data);
    });
    let out = child.wait_with_output().unwrap();
    let _ = writer.join();
    out
}

type Lzma2Encoder = <Lzma2 as Algorithm>::Encoder;

fn flush_words(n: usize, seed: u32) -> Vec<u8> {
    const WORDS: [&[u8]; 8] = [
        b"alpha ",
        b"beta ",
        b"gamma ",
        b"delta ",
        b"epsilon ",
        b"zeta ",
        b"eta ",
        b"theta ",
    ];
    let mut x = seed;
    let mut out = Vec::with_capacity(n + 8);
    while out.len() < n {
        x = x.wrapping_mul(1_103_515_245).wrapping_add(12_345);
        out.extend_from_slice(WORDS[((x >> 16) & 7) as usize]);
    }
    out.truncate(n);
    out
}

fn flush_noise(n: usize, seed: u32) -> Vec<u8> {
    let mut x = seed;
    (0..n)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 16) as u8
        })
        .collect()
}

/// Segments fed between flushes: tiny, compressible, incompressible, and
/// one longer than the encoder's 1 MiB chunk lookahead so a flush lands
/// after a full chunk has already gone out.
fn flush_segments() -> Vec<Vec<u8>> {
    vec![
        b"x".to_vec(),
        flush_words(100, 1),
        flush_words(5_000, 2),
        flush_noise(3_000, 3),
        flush_words(1_200_000, 4),
        b"tail".to_vec(),
        flush_words(70_000, 5),
    ]
}

/// Incompressible on its own, so a second copy is cheap only when it can
/// back-reference the first.
fn flush_text(n: usize) -> Vec<u8> {
    flush_noise(n, 11)
}

/// Same check as the xz tests, through `xz --format=raw`: a raw LZMA2
/// stream cut at a flush point decodes to everything given before it.
#[test]
fn flushes_interoperate_with_system_xz_raw() {
    let available = std::process::Command::new("xz")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !available {
        println!("skipping: xz not installed");
        return;
    }
    for mode in [Flush::Sync, Flush::Full] {
        let mut enc = Lzma2::encoder();
        let mut wire = Vec::new();
        let mut given = Vec::new();
        let args = ["--format=raw", "--lzma2=dict=4MiB", "-d", "-c"];
        for seg in flush_segments() {
            flush_test_encode(&mut enc, &seg, 4096, &mut wire);
            given.extend_from_slice(&seg);
            flush_test_flush(&mut enc, mode, 4096, &mut wire);
            let out = run_tool("xz", &args, &wire);
            assert!(
                out.stdout == given,
                "xz raw on a stream cut at a {mode:?} flush after {} bytes wrote {} bytes",
                given.len(),
                out.stdout.len()
            );
        }
        flush_test_finish(&mut enc, 4096, &mut wire);
        let out = run_tool("xz", &args, &wire);
        assert!(out.status.success() && out.stdout == given, "{mode:?}");
    }
}

// ─── hand-built compressed chunks ───────────────────────────────────────

/// A minimal LZMA range encoder for hand-built payloads. Every bit goes
/// through a probability that is still at its initial value (1/2), which is
/// all the short payloads below need.
struct FreshBitEncoder {
    low: u64,
    range: u32,
    cache: u8,
    cache_size: u64,
    out: Vec<u8>,
}

impl FreshBitEncoder {
    fn new() -> Self {
        Self {
            low: 0,
            range: 0xFFFF_FFFF,
            cache: 0,
            cache_size: 1,
            out: Vec::new(),
        }
    }

    fn shift_low(&mut self) {
        if (self.low as u32) < 0xFF00_0000 || (self.low >> 32) != 0 {
            let carry = (self.low >> 32) as u8;
            let mut byte = self.cache;
            loop {
                self.out.push(byte.wrapping_add(carry));
                byte = 0xFF;
                self.cache_size -= 1;
                if self.cache_size == 0 {
                    break;
                }
            }
            self.cache = (self.low >> 24) as u8;
        }
        self.cache_size += 1;
        self.low = (self.low & 0x00FF_FFFF) << 8;
    }

    fn bits(&mut self, bits: &[u8]) {
        for &bit in bits {
            let bound = (self.range >> 11) * 1024;
            if bit == 0 {
                self.range = bound;
            } else {
                self.low += bound as u64;
                self.range -= bound;
            }
            while self.range < 1 << 24 {
                self.range <<= 8;
                self.shift_low();
            }
        }
    }

    fn finish(mut self) -> Vec<u8> {
        for _ in 0..5 {
            self.shift_low();
        }
        self.out
    }
}

/// The LZMA payload of a chunk that is one match of length 2 at distance 9
/// (the bytes 9 and 8 back), decoded from a freshly reset state at a
/// position that is a multiple of 4.
fn match_len2_dist9_payload() -> Vec<u8> {
    let mut rc = FreshBitEncoder::new();
    rc.bits(&[1]); // is_match: a match
    rc.bits(&[0]); // is_rep: a new distance
    rc.bits(&[0, 0, 0, 0]); // length: "low" choice, symbol 0 → 2
    rc.bits(&[0, 0, 0, 1, 1, 0]); // distance slot 6 → base 8, 2 more bits
    rc.bits(&[0, 0]); // the 2 reverse-coded bits → distance 8 (9 back)
    rc.finish()
}

/// `control` + sizes + properties (lc=3, lp=0, pb=2) + `payload`, for a
/// compressed chunk of `uncomp` bytes carrying a properties byte.
fn compressed_chunk(control: u8, uncomp: usize, payload: &[u8]) -> Vec<u8> {
    assert!(control >= 0xC0 && uncomp - 1 < 1 << 16);
    let mut c = vec![control, ((uncomp - 1) >> 8) as u8, (uncomp - 1) as u8];
    c.extend_from_slice(&[((payload.len() - 1) >> 8) as u8, (payload.len() - 1) as u8]);
    c.push(0x5D);
    c.extend_from_slice(payload);
    c
}

fn stored_chunk(control: u8, data: &[u8]) -> Vec<u8> {
    let mut c = vec![
        control,
        ((data.len() - 1) >> 8) as u8,
        (data.len() - 1) as u8,
    ];
    c.extend_from_slice(data);
    c
}

/// After a dictionary reset the next compressed chunk must carry new
/// properties (liblzma's `need_properties`): a `0x80..=0xBF` chunk used to
/// be decoded with made-up default properties.
#[test]
fn compressed_chunk_after_dict_reset_needs_properties() {
    let first: &[u8] = b"0123456789abcdef";
    let payload = match_len2_dist9_payload();
    let with_props = compressed_chunk(0xC0, 2, &payload);
    // The same chunk without its properties byte: state reset only (0xA0)
    // or no reset at all (0x80).
    let without_props = |control: u8| {
        let mut c = with_props.clone();
        c[0] = control;
        c.remove(5);
        c
    };
    let decode = |chunks: &[&[u8]]| {
        let s = [&chunks.concat()[..], &[0x00]].concat();
        decode_all(&s, DecoderConfig::default(), 64)
    };
    let stored = stored_chunk(0x01, first);

    for control in [0xA0, 0x80] {
        // Straight after the stream's first (dictionary-reset) chunk.
        let r = decode(&[&stored, &without_props(control)]);
        assert_eq!(r, Err(Error::Corrupt), "{control:#x}");
        // Properties given once do not survive a later dictionary reset.
        let r = decode(&[&stored, &with_props, &stored, &without_props(control)]);
        assert_eq!(r, Err(Error::Corrupt), "{control:#x} after a later reset");
    }
    // With properties in force, a state-reset chunk needs none (the
    // payload expects a fresh state, so 0xA0 it is). A stored chunk that
    // keeps the dictionary (0x02) keeps the properties too.
    let got = decode(&[&stored, &with_props, &without_props(0xA0)]).unwrap();
    assert_eq!(got, b"0123456789abcdef789a");
    let more = stored_chunk(0x02, b"..");
    let got = decode(&[&stored, &with_props, &more, &without_props(0xA0)]).unwrap();
    assert_eq!(got, b"0123456789abcdef78..bc");

    // The stream's first chunk must reset the dictionary.
    assert_eq!(decode(&[&with_props]), Err(Error::Corrupt));
    assert_eq!(decode(&[&without_props(0xA0)]), Err(Error::Corrupt));
    assert_eq!(decode(&[&more]), Err(Error::Corrupt));
}

/// A compressed chunk's payload must be exactly what the range coder
/// reads: once the chunk's output is complete, every compressed byte has
/// been consumed and the coder's `code` is zero (liblzma's
/// `rc_is_finished` plus its Compressed Size check). Bytes riding along
/// inside the chunk's Compressed Size used to be skipped silently.
#[test]
fn compressed_chunk_must_use_its_whole_payload() {
    let data = b"hello hello hello hello hello hello hello hello ".repeat(20);
    let s = encode_all(&data, 1 << 16);
    // One full-reset chunk (6 header bytes), then the end marker.
    let comp = (((s[3] as usize) << 8) | s[4] as usize) + 1;
    assert!(s[0] >= 0xE0 && s.len() == 6 + comp + 1);
    let decode = |s: &[u8]| decode_all(s, DecoderConfig::default(), data.len());
    assert_eq!(decode(&s).as_deref(), Ok(&data[..]));

    // Extra bytes inside the chunk, after the LZMA data.
    for slack in [&[0x00][..], &[0x00; 5], &[0xDE, 0xAD, 0xBE, 0xEF, 1, 2, 3]] {
        let mut bad = s[..6 + comp].to_vec();
        let new_comp = comp + slack.len() - 1;
        bad[3] = (new_comp >> 8) as u8;
        bad[4] = new_comp as u8;
        bad.extend_from_slice(slack);
        bad.push(0x00);
        assert_eq!(decode(&bad), Err(Error::Corrupt), "slack {slack:?}");
        // One byte at a time, too.
        let mut dec = Lzma2::decoder_with(DecoderConfig::default());
        let mut out = vec![0u8; data.len() + 16];
        let mut written = 0;
        let mut failed = false;
        for b in &bad {
            match dec.decode(core::slice::from_ref(b), &mut out[written..]) {
                Ok((p, _)) => written += p.written,
                Err(e) => {
                    assert_eq!(e, Error::Corrupt);
                    failed = true;
                    break;
                }
            }
        }
        assert!(failed, "slack {slack:?} accepted bytewise");
    }

    // The range coder's final bytes are not padding either: with the last
    // byte changed, the coder does not end on `code == 0`.
    let mut bad = s.clone();
    bad[5 + comp] ^= 0x01;
    assert_eq!(decode(&bad), Err(Error::Corrupt));

    // The hand-built chunk from above ends cleanly; cut short by a byte,
    // or padded by one, it does not.
    let first = stored_chunk(0x01, b"0123456789abcdef");
    let payload = match_len2_dist9_payload();
    let good = [&first[..], &compressed_chunk(0xC0, 2, &payload), &[0x00]].concat();
    assert_eq!(decode(&good).as_deref(), Ok(&b"0123456789abcdef78"[..]));
    let padded = [&payload[..], &[0x00]].concat();
    let bad = [&first[..], &compressed_chunk(0xC0, 2, &padded), &[0x00]].concat();
    assert_eq!(decode(&bad), Err(Error::Corrupt));
}

/// A dictionary reset keeps the decoder's dictionary buffer (re-allocating
/// it per `0x01` chunk was a CPU DoS), so the bytes from before the reset
/// are still in memory: no match may reach them.
#[test]
fn match_cannot_reach_bytes_from_before_a_dictionary_reset() {
    let first: &[u8] = b"0123456789abcdef";
    let second: &[u8] = b"ABCDEFGH";
    let tail = compressed_chunk(0xC0, 2, &match_len2_dist9_payload());

    // The hand-built match works: straight after `first` it copies the
    // bytes 9 and 8 back.
    let mut s = stored_chunk(0x01, first);
    s.extend_from_slice(&tail);
    s.push(0x00);
    let got = decode_all(&s, DecoderConfig::default(), 64).unwrap();
    assert_eq!(got, b"0123456789abcdef78");

    // With `second` appended to the same dictionary (0x02: no reset) the
    // match reaches back into `first`.
    let mut s = stored_chunk(0x01, first);
    s.extend_from_slice(&stored_chunk(0x02, second));
    s.extend_from_slice(&tail);
    s.push(0x00);
    let got = decode_all(&s, DecoderConfig::default(), 64).unwrap();
    assert_eq!(got, b"0123456789abcdefABCDEFGHfA");

    // After a dictionary reset (0x01) only `second`'s 8 bytes exist: a
    // match 9 back is corrupt, not a read of what the buffer still holds.
    let mut s = stored_chunk(0x01, first);
    s.extend_from_slice(&stored_chunk(0x01, second));
    s.extend_from_slice(&tail);
    s.push(0x00);
    let r = decode_all(&s, DecoderConfig::default(), 64);
    assert_eq!(r, Err(Error::Corrupt));

    // The same through a full-reset compressed chunk: 0xE0 resets the
    // dictionary itself, so nothing at all can be referenced.
    let mut s = stored_chunk(0x01, first);
    s.extend_from_slice(&compressed_chunk(0xE0, 2, &match_len2_dist9_payload()));
    s.push(0x00);
    let r = decode_all(&s, DecoderConfig::default(), 64);
    assert_eq!(r, Err(Error::Corrupt));
}

/// The dictionary buffer grows with the output instead of being allocated
/// up front, and wraps only at the configured size: decode data several
/// times larger than a small dictionary, through stored and compressed
/// chunks, with matches all along (so also across the wrap).
#[test]
fn lazily_grown_dictionary_wraps_at_its_size() {
    let mut s = stored_chunk(0x01, b"0123456789abcdef");
    let mut want: Vec<u8> = b"0123456789abcdef".to_vec();
    let payload = match_len2_dist9_payload();
    let mut i = 0u32;
    while want.len() < 20_000 {
        // Sized to keep the position a multiple of 4 for the hand-built
        // payload: 4k + 2 stored bytes, then the 2 matched ones.
        let stored: Vec<u8> = (0..(10 + 4 * (i % 300)))
            .map(|j| j.wrapping_mul(i + 7) as u8)
            .collect();
        s.extend_from_slice(&stored_chunk(0x02, &stored));
        want.extend_from_slice(&stored);
        s.extend_from_slice(&compressed_chunk(0xC0, 2, &payload));
        let n = want.len();
        want.extend_from_within(n - 9..n - 7);
        i += 1;
    }
    s.push(0x00);
    let got = decode_all(&s, DecoderConfig::with_dict_size(4096), want.len()).unwrap();
    assert!(got == want);
}

// ─── contiguous output ──────────────────────────────────────────────────

/// Decode `stream` through the [`ContiguousDecoder`] calls the way a caller
/// growing its buffer would: input in `in_chunk`-byte pieces, an output
/// buffer of `start` bytes which, whenever the decoder asks for room, is
/// replaced by a *new* allocation holding the same decoded prefix — `step`
/// bytes longer, plus 1/`ratio` of its length when `ratio` is not 0 (so
/// that a large output does not take a quadratic number of copies). The
/// old buffer is scribbled over first and the new tail is junk: the decoder
/// may rely on neither. `finish_contiguous` is called once the input is
/// used up.
///
/// Returns what was decoded, the input consumed (or the error), and how
/// often the buffer had to grow.
fn drive_contiguous<D: ContiguousDecoder>(
    dec: &mut D,
    stream: &[u8],
    in_chunk: usize,
    start: usize,
    (step, ratio): (usize, usize),
) -> (Vec<u8>, Result<usize, Error>, usize) {
    let mut out = vec![0xA5u8; start];
    let (mut filled, mut pos, mut grows) = (0usize, 0usize, 0usize);
    let result = loop {
        let end = pos.saturating_add(in_chunk).min(stream.len());
        let feeding = pos < stream.len();
        let r = if feeding {
            dec.decode_contiguous(&stream[pos..end], &mut out, filled)
        } else {
            dec.finish_contiguous(&mut out, filled)
        };
        let (p, status) = match r {
            Ok(v) => v,
            Err(e) => break Err(e),
        };
        pos += p.consumed;
        filled += p.written;
        assert!(pos <= end && filled <= out.len());
        match status {
            Status::StreamEnd => break Ok(pos),
            Status::OutputFull if filled == out.len() => {
                let extra = step + out.len().checked_div(ratio).unwrap_or(0);
                let junk = if grows % 2 == 0 { 0x5A } else { 0xC3 };
                let mut longer = vec![junk; out.len() + extra];
                longer[..filled].copy_from_slice(&out[..filled]);
                out.fill(0xEE);
                out = longer;
                grows += 1;
            }
            Status::OutputFull => assert!(
                p.written > 0 || p.consumed > 0,
                "OutputFull with room left and nothing done"
            ),
            Status::InputEmpty => assert!(feeding && pos == end, "InputEmpty with input left"),
        }
    };
    out.truncate(filled);
    (out, result, grows)
}

/// What the streaming calls made of `stream` — its output, or the error —
/// is what every way of driving the contiguous calls must give: from an
/// empty buffer grown in small steps, a byte of input at a time, and with
/// a buffer of exactly the decoded size (which then never has to grow).
fn assert_contiguous_agrees(stream: &[u8], cfg: DecoderConfig, want: &Result<Vec<u8>, Error>) {
    let len = want.as_ref().map_or(0, |v| v.len());
    let fine = if len <= 2048 { (1, 0) } else { (1, 16) };
    for (in_chunk, start, grow) in [
        (usize::MAX, 0, fine),
        (1, 1, (3, 8)),
        (usize::MAX, len, fine),
        (5, len, (64, 4)),
    ] {
        let mut dec = Lzma2::decoder_with(cfg);
        let (out, r, grows) = drive_contiguous(&mut dec, stream, in_chunk, start, grow);
        let got = r.map(|_| out);
        assert!(
            got == *want,
            "contiguous (in {in_chunk}, start {start}, grow {grow:?}): {:?}, streaming: {:?}",
            got.as_ref().map(|v| v.len()),
            want.as_ref().map(|v| v.len()),
        );
        if want.is_ok() && start == len {
            assert_eq!(grows, 0, "a buffer of the exact size had to grow");
        }
    }
}

/// Encoder output — plain, and with Sync and Full flushes — decodes the
/// same in both modes (`decode_all` compares them), and so does every
/// flushed prefix, which never reaches the end marker.
#[test]
fn contiguous_matches_streaming_on_encoder_output() {
    let mut data = flush_text(70_000);
    data.extend_from_slice(&flush_noise(9_000, 5));
    data.extend_from_slice(&vec![b'z'; 30_000]);
    data.extend_from_slice(&flush_words(40_000, 11));
    for out_chunk in [1 << 16, 13] {
        let wire = encode_all(&data, out_chunk);
        let got = decode_all(&wire, DecoderConfig::default(), data.len()).unwrap();
        assert!(got == data);
    }
    for mode in [Flush::Sync, Flush::Full] {
        let mut enc = Lzma2::encoder_with(());
        let mut wire = Vec::new();
        let mut given = Vec::new();
        let segments = [
            b"x".to_vec(),
            flush_words(100, 1),
            flush_words(5_000, 2),
            flush_noise(3_000, 3),
            flush_words(60_000, 4),
            b"tail".to_vec(),
            flush_words(20_000, 5),
        ];
        for seg in segments {
            flush_test_encode(&mut enc, &seg, 4096, &mut wire);
            given.extend_from_slice(&seg);
            flush_test_flush(&mut enc, mode, 4096, &mut wire);
            // The unterminated prefix: everything given so far comes out,
            // and the decoder waits for more.
            let mut dec = Lzma2::decoder_with(DecoderConfig::default());
            let mut out = vec![0u8; given.len()];
            let (p, status) = dec.decode_contiguous(&wire, &mut out, 0).unwrap();
            assert_eq!((p.consumed, status), (wire.len(), Status::InputEmpty));
            assert!(out[..p.written] == given, "{mode:?} prefix");
            assert_eq!(
                dec.finish_contiguous(&mut out, p.written),
                Err(Error::UnexpectedEnd)
            );
        }
        flush_test_finish(&mut enc, 4096, &mut wire);
        let got = decode_all(&wire, DecoderConfig::default(), given.len()).unwrap();
        assert!(got == given, "{mode:?}");
    }
}

/// The contiguous buffer holds everything decoded since the start of the
/// stream, but the history a match may use is still what the dictionary
/// would hold: nothing from before a dictionary reset. The hand-built
/// streams of `match_cannot_reach_bytes_from_before_a_dictionary_reset`,
/// with the output cut at every possible length.
#[test]
fn contiguous_match_cannot_reach_before_a_dictionary_reset() {
    let first: &[u8] = b"0123456789abcdef";
    let second: &[u8] = b"ABCDEFGH";
    let tail = compressed_chunk(0xC0, 2, &match_len2_dist9_payload());
    let decode = |chunks: &[&[u8]], start: usize| {
        let s = [&chunks.concat()[..], &[0x00]].concat();
        let mut dec = Lzma2::decoder_with(DecoderConfig::default());
        let (out, r, _) = drive_contiguous(&mut dec, &s, usize::MAX, start, (1, 0));
        r.map(|_| out)
    };
    for start in 0..=32 {
        // Within one dictionary the match reaches whatever is 9 back, in
        // the same chunk's bytes or an earlier chunk's.
        let got = decode(&[&stored_chunk(0x01, first), &tail], start);
        assert_eq!(got.as_deref(), Ok(&b"0123456789abcdef78"[..]));
        let got = decode(
            &[
                &stored_chunk(0x01, first),
                &stored_chunk(0x02, second),
                &tail,
            ],
            start,
        );
        assert_eq!(got.as_deref(), Ok(&b"0123456789abcdefABCDEFGHfA"[..]));

        // After a reset only `second`'s 8 bytes are history, although the
        // 16 before them are right there in the buffer.
        let got = decode(
            &[
                &stored_chunk(0x01, first),
                &stored_chunk(0x01, second),
                &tail,
            ],
            start,
        );
        assert_eq!(got, Err(Error::Corrupt), "start {start}");
        // A full-reset compressed chunk has no history at all.
        let full_reset = compressed_chunk(0xE0, 2, &match_len2_dist9_payload());
        let got = decode(&[&stored_chunk(0x01, first), &full_reset], start);
        assert_eq!(got, Err(Error::Corrupt), "start {start}");
    }
}

/// A match further back than the configured dictionary size is corrupt in
/// both modes, even though the contiguous buffer still has the bytes.
#[test]
fn contiguous_distances_are_bounded_by_the_dictionary_size() {
    // 6000 bytes with no long repeats (but compressible: 4 bits each),
    // then the first 300 again: a match 6000 back.
    let mut s = 0x1234_5678u32;
    let mut data: Vec<u8> = (0..6000)
        .map(|_| {
            s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            b'a' + (s >> 28) as u8
        })
        .collect();
    data.extend_from_within(..300);
    let wire = encode_all(&data, 1 << 16);
    assert!(wire.len() < 4000, "the repeat was not found");

    let roomy = DecoderConfig::with_dict_size(8192);
    assert!(decode_all(&wire, roomy, data.len()).unwrap() == data);
    // (`decode_all` checks that the contiguous calls fail alike.)
    let tight = DecoderConfig::with_dict_size(4096);
    assert_eq!(decode_all(&wire, tight, data.len()), Err(Error::Corrupt));
    let mut dec = Lzma2::decoder_with(tight);
    let mut out = vec![0u8; data.len()];
    assert_eq!(
        dec.decode_contiguous(&wire, &mut out, 0),
        Err(Error::Corrupt)
    );
}

/// A stream is decoded with the streaming calls or the contiguous ones,
/// not both; `filled` must be what the decoder has written. Either mistake
/// is refused without harming the decoder, and `reset` allows either mode
/// again.
#[test]
fn contiguous_and_streaming_calls_do_not_mix() {
    let mut data = flush_noise(70_000, 9);
    data.extend_from_slice(&flush_text(80_000));
    let wire = encode_all(&data, 1 << 16);
    let (head, rest) = wire.split_at(wire.len() / 2);
    let mut out = vec![0u8; data.len()];
    let mut scratch = vec![0u8; data.len()];

    // Contiguous first: the streaming calls are refused, and decoding goes
    // on undisturbed afterwards.
    let mut dec = Lzma2::decoder_with(DecoderConfig::default());
    let (p, status) = dec.decode_contiguous(head, &mut out, 0).unwrap();
    assert_eq!((p.consumed, status), (head.len(), Status::InputEmpty));
    let mut filled = p.written;
    assert!(filled > 0);
    assert_eq!(dec.decode(rest, &mut scratch), Err(Error::Unsupported));
    assert_eq!(dec.finish(&mut scratch), Err(Error::Unsupported));
    assert_eq!(
        dec.discard_output(rest, 10).map(|_| ()),
        Err(Error::Unsupported)
    );
    // A wrong `filled`: too small, too large, beyond the buffer.
    for bad in [0, filled - 1, filled + 1, out.len() + 1] {
        if bad != filled {
            assert_eq!(
                dec.decode_contiguous(rest, &mut out, bad),
                Err(Error::Unsupported),
                "filled {bad} instead of {filled}"
            );
            assert_eq!(
                dec.finish_contiguous(&mut out, bad),
                Err(Error::Unsupported)
            );
        }
    }
    let (p, status) = dec.decode_contiguous(rest, &mut out, filled).unwrap();
    filled += p.written;
    assert_eq!(status, Status::StreamEnd);
    assert_eq!(
        dec.finish_contiguous(&mut out, filled),
        Ok((Default::default(), Status::StreamEnd))
    );
    assert!(out[..filled] == data);

    // Streaming first: the contiguous calls are refused.
    dec.reset();
    let (p, _) = dec.decode(head, &mut scratch).unwrap();
    let n = p.written;
    assert_eq!(
        dec.decode_contiguous(rest, &mut out, 0),
        Err(Error::Unsupported)
    );
    assert_eq!(dec.finish_contiguous(&mut out, 0), Err(Error::Unsupported));
    let (p, status) = dec.decode(rest, &mut scratch[n..]).unwrap();
    assert_eq!(status, Status::StreamEnd);
    assert!(scratch[..n + p.written] == data);

    // After a reset, contiguous again — from `filled` 0.
    dec.reset();
    assert_eq!(
        dec.decode_contiguous(&wire, &mut out, filled),
        Err(Error::Unsupported)
    );
    out.fill(0);
    let (p, status) = dec.decode_contiguous(&wire, &mut out, 0).unwrap();
    assert_eq!(status, Status::StreamEnd);
    assert!(out[..p.written] == data);
}

/// Truncated at any point, a stream gives the same bytes and the same
/// error in both modes.
#[test]
fn contiguous_truncation_matches_streaming() {
    let mut data = flush_text(2500);
    data.extend_from_slice(&flush_noise(700, 3));
    data.extend_from_slice(&flush_text(900));
    let wire = encode_all(&data, 1 << 16);
    for cut in 0..wire.len() {
        let cut = &wire[..cut];
        // Streaming: all of it, then `finish`.
        let mut dec = Lzma2::decoder_with(DecoderConfig::default());
        let mut want = vec![0u8; data.len() + 1];
        let (p, status) = dec.decode(cut, &mut want).unwrap();
        assert_eq!(status, Status::InputEmpty);
        want.truncate(p.written);
        assert_eq!(dec.finish(&mut []), Err(Error::UnexpectedEnd));

        for (in_chunk, start, grow) in [(usize::MAX, 0, (7, 0)), (3, data.len(), (1, 0))] {
            let mut dec = Lzma2::decoder_with(DecoderConfig::default());
            let (out, r, _) = drive_contiguous(&mut dec, cut, in_chunk, start, grow);
            assert_eq!(r, Err(Error::UnexpectedEnd), "cut at {}", cut.len());
            assert!(out == want, "cut at {}", cut.len());
        }
    }
}
