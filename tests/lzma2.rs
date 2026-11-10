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
use compcol::{Algorithm, Decoder, Encoder, Error, Flush, Status};

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

fn decode_all(stream: &[u8], cfg: DecoderConfig, out_cap: usize) -> Result<Vec<u8>, Error> {
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
