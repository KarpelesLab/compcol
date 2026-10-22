#![cfg(feature = "lha")]
//! Streaming round-trip + error-path tests for the LHA/LZH methods.

use compcol::lha::{DecoderConfig, Lh1, Lh2, Lh4, Lh5, Lh6, Lh7};
use compcol::{Algorithm, Decoder, Encoder, Error, Status};

/// Encode `data` with `enc`, feeding `in_chunk` bytes at a time and
/// draining into `out_chunk`-sized output buffers, exercising the
/// resumable streaming contract.
fn run_stream<F>(mut step: F, data: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8>
where
    F: FnMut(&[u8], &mut [u8]) -> (compcol::Progress, Status),
{
    // Feed `data` to `step` (an encode or decode closure) in `in_chunk`
    // slices, draining `out_chunk`-sized output buffers each call. `step`
    // owns advancing the codec; we just present input windows.
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut consumed = 0usize;
    while consumed < data.len() {
        let end = (consumed + in_chunk.max(1)).min(data.len());
        loop {
            let (p, status) = step(&data[consumed..end], &mut buf);
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::OutputFull => continue,
                _ => break,
            }
        }
    }
    out
}

fn encode_chunked<E: Encoder>(
    mut enc: E,
    data: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Vec<u8> {
    let mut out = run_stream(
        |inp, buf| enc.encode(inp, buf).unwrap(),
        data,
        in_chunk,
        out_chunk,
    );
    let mut buf = vec![0u8; out_chunk.max(1)];
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
    }
    out
}

fn decode_chunked<D: Decoder>(
    mut dec: D,
    data: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Vec<u8> {
    let mut out = run_stream(
        |inp, buf| dec.decode(inp, buf).unwrap(),
        data,
        in_chunk,
        out_chunk,
    );
    let mut buf = vec![0u8; out_chunk.max(1)];
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    out
}

/// Round-trip `data` through the raw (un-prefixed) payload.
///
/// `with_len = false` exercises the streaming `finish()` path (no length —
/// the block-structured static methods self-terminate). `with_len = true`
/// supplies the uncompressed size out of band via `DecoderConfig::with_len`
/// (required by `lh1`, valid for all).
fn roundtrip_mode<A: Algorithm<DecoderConfig = DecoderConfig>>(data: &[u8], with_len: bool) {
    // A few chunk-size combinations to exercise resumability.
    for &(ic, oc) in &[(1 << 20, 1 << 20), (1, 1), (7, 3), (64, 16)] {
        let enc = A::encoder();
        let encoded = encode_chunked(enc, data, ic, oc);
        let dec = if with_len {
            A::decoder_with(DecoderConfig::with_len(data.len()))
        } else {
            A::decoder()
        };
        let decoded = decode_chunked(dec, &encoded, ic, oc);
        assert_eq!(
            decoded,
            data,
            "round-trip mismatch for {} (with_len={}, in={}, out={}, len={})",
            A::NAME,
            with_len,
            ic,
            oc,
            data.len()
        );
    }
}

/// Static methods (lh4/5/6/7) must round-trip both via `finish()` and with an
/// explicit length.
fn roundtrip_static<A: Algorithm<DecoderConfig = DecoderConfig>>(data: &[u8]) {
    roundtrip_mode::<A>(data, false);
    roundtrip_mode::<A>(data, true);
}

fn sample_inputs() -> Vec<Vec<u8>> {
    let mut v: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"a".to_vec(),
        b"hello world".to_vec(),
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_vec(),
        b"abcabcabcabcabcabcabcabcabcabcabcabcabcabcabc".to_vec(),
    ];
    // Repeated phrase to stress matches and the dictionary.
    let mut big = Vec::new();
    for i in 0..2000u32 {
        big.extend_from_slice(format!("The quick brown fox {} jumps. ", i % 13).as_bytes());
    }
    v.push(big);
    // Pseudo-random but deterministic bytes (low compressibility).
    let mut rng = 0x12345678u32;
    let mut rnd = Vec::with_capacity(5000);
    for _ in 0..5000 {
        rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
        rnd.push((rng >> 16) as u8);
    }
    v.push(rnd);
    // All 256 byte values, several times.
    let mut allbytes = Vec::new();
    for _ in 0..40 {
        for b in 0..=255u8 {
            allbytes.push(b);
        }
    }
    v.push(allbytes);
    v
}

#[test]
fn roundtrip_lh5() {
    for data in sample_inputs() {
        roundtrip_static::<Lh5>(&data);
    }
}

#[test]
fn roundtrip_lh4() {
    for data in sample_inputs() {
        roundtrip_static::<Lh4>(&data);
    }
}

#[test]
fn roundtrip_lh6() {
    for data in sample_inputs() {
        roundtrip_static::<Lh6>(&data);
    }
}

#[test]
fn roundtrip_lh7() {
    for data in sample_inputs() {
        roundtrip_static::<Lh7>(&data);
    }
}

#[test]
fn roundtrip_lh1() {
    for data in sample_inputs() {
        roundtrip_mode::<Lh1>(&data, true);
    }
}

#[test]
fn roundtrip_lh2() {
    // lh2 is continuous + size-terminated like lh1, so it needs with_len.
    for data in sample_inputs() {
        roundtrip_mode::<Lh2>(&data, true);
    }
}

#[test]
fn lh2_without_len_refuses() {
    // Non-empty lh2 stream with no out-of-band length must error (it has no
    // in-band end marker), not emit garbage.
    let data = b"some data to compress with lh2, repeated a bit".repeat(8);
    let payload = encode_chunked(Lh2::encoder(), &data, 1 << 16, 1 << 16);
    let mut dec = Lh2::decoder(); // default config: no expected_len
    let mut out = vec![0u8; 4096];
    let _ = dec.decode(&payload, &mut out); // buffers the stream
    assert!(matches!(dec.finish(&mut out), Err(Error::Unsupported)));
}

#[test]
fn large_window_match_lh2() {
    // A match reachable only with lh2's 8 KiB window.
    let mut data = vec![0u8; 20_000];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 241) as u8;
    }
    let head: Vec<u8> = data[..6000].to_vec();
    data.extend_from_slice(&head);
    roundtrip_mode::<Lh2>(&data, true);
}

#[test]
fn large_window_match_lh7() {
    // A match at a distance only reachable with lh7's large (64 KiB) window.
    let mut data = vec![0u8; 100_000];
    for (i, b) in data.iter_mut().enumerate() {
        *b = (i % 251) as u8;
    }
    // Append a copy of the first 5000 bytes so it back-references far.
    let head: Vec<u8> = data[..5000].to_vec();
    data.extend_from_slice(&head);
    roundtrip_static::<Lh7>(&data);
}

// ─── error paths: crafted/truncated input must never panic ───────────────

#[test]
fn truncated_payload_errors_cleanly() {
    // Encode something, then chop the payload and confirm a clean error
    // (not a panic) from finish().
    let data = b"the quick brown fox jumps over the lazy dog, repeatedly!".repeat(20);
    let enc = Lh5::encoder();
    let encoded = encode_chunked(enc, &data, 1 << 16, 1 << 16);
    // Keep only the first few bytes of the raw payload.
    let truncated = &encoded[..(encoded.len().min(8))];
    let mut dec = Lh5::decoder();
    let mut buf = vec![0u8; 4096];
    let (_p, _s) = dec.decode(truncated, &mut buf).unwrap();
    let res = dec.finish(&mut buf);
    // Either it errors, or (if the few bytes happened to decode short) it
    // returns fewer bytes — but it must not panic and must not over-produce.
    match res {
        Ok((p, _)) => assert!(p.written <= data.len()),
        Err(e) => assert!(matches!(
            e,
            Error::Corrupt
                | Error::UnexpectedEnd
                | Error::InvalidHuffmanTree
                | Error::InvalidDistance
        )),
    }
}

#[test]
fn garbage_payload_errors_cleanly() {
    // Random junk fed as a raw payload must never panic — the decoder either
    // errors or terminates with bounded output. `lh1` (no length) refuses
    // outright with `Unsupported`; the static methods decode-until-EOF and
    // either error on the malformed bitstream or stop.
    let mut stream = Vec::new();
    let mut rng = 0xdead_beefu32;
    for _ in 0..200 {
        rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
        stream.push((rng >> 16) as u8);
    }
    let decoders: [Box<dyn Decoder>; 3] = [
        Box::new(Lh5::decoder()),
        Box::new(Lh1::decoder()),
        Box::new(Lh6::decoder()),
    ];
    for mut dec in decoders {
        let mut buf = vec![0u8; 8192];
        let _ = dec.decode(&stream, &mut buf);
        // Must not panic; output is bounded well under any bomb threshold.
        let mut produced = 0usize;
        while let Ok((p, status)) = dec.finish(&mut buf) {
            produced += p.written;
            assert!(produced <= 4 * 1024 * 1024);
            if matches!(status, Status::StreamEnd) || p.written == 0 {
                break;
            }
        }
    }
}

#[test]
fn empty_input_to_decoder_is_unexpected_end_or_empty() {
    // A decoder given no bytes at all: finish should yield empty output
    // (we treat a totally empty stream as zero-length) without panicking.
    let mut dec = Lh5::decoder();
    let mut buf = vec![0u8; 16];
    let (p, status) = dec.finish(&mut buf).unwrap();
    assert_eq!(p.written, 0);
    assert!(matches!(status, Status::StreamEnd));
}

#[test]
fn names_registered() {
    #[cfg(feature = "factory")]
    {
        let names = compcol::factory::names();
        for n in ["lh1", "lh2", "lh4", "lh5", "lh6", "lh7"] {
            assert!(names.contains(&n), "{n} not registered");
            assert!(compcol::factory::encoder_by_name(n).is_some());
            assert!(compcol::factory::decoder_by_name(n).is_some());
        }
    }
}

/// Deterministic, poorly compressible bytes.
fn noise(n: usize, seed: u32) -> Vec<u8> {
    let mut rng = seed;
    (0..n)
        .map(|_| {
            rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
            (rng >> 16) as u8
        })
        .collect()
}

fn vec_roundtrip<A: Algorithm<DecoderConfig = DecoderConfig>>(data: &[u8]) {
    let encoded = compcol::vec::compress_to_vec::<A>(data).unwrap();
    let decoded = compcol::vec::decompress_to_vec::<A>(&encoded)
        .unwrap_or_else(|e| panic!("{}: {e:?}", A::NAME));
    assert!(decoded == data, "{}: round-trip mismatch", A::NAME);
    let decoded =
        compcol::vec::decompress_to_vec_with::<A>(&encoded, DecoderConfig::with_len(data.len()))
            .unwrap();
    assert!(
        decoded == data,
        "{}: round-trip mismatch (with_len)",
        A::NAME
    );
}

#[test]
fn static_methods_split_more_than_65535_tokens_into_blocks() {
    // ~100k literal tokens: a block's code count is a 16-bit field, so the
    // encoder must start new blocks. It used to write one block with the count
    // truncated mod 65536, which decoded as garbage / `InvalidHuffmanTree`.
    let data = noise(100_000, 0xDEAD_BEEF);
    vec_roundtrip::<Lh4>(&data);
    vec_roundtrip::<Lh5>(&data);
    vec_roundtrip::<Lh6>(&data);
    vec_roundtrip::<Lh7>(&data);
}

#[test]
fn lh4_matches_stay_within_its_4k_dictionary() {
    // The only repeats are 5000 bytes apart: within lh5's 8 KiB reach but
    // beyond lh4's 4 KiB dictionary, which the lh4 encoder used to ignore
    // (it shares lh5's position alphabet), producing `InvalidDistance`.
    let chunk = noise(5000, 42);
    let data = chunk.repeat(3);
    vec_roundtrip::<Lh4>(&data);
    vec_roundtrip::<Lh5>(&data);
}

/// Hand-assemble MSB-first bits.
fn pack_bits(fields: &[(u32, u32)]) -> Vec<u8> {
    let (mut out, mut acc, mut n) = (Vec::new(), 0u64, 0u32);
    for &(bits, v) in fields {
        acc = (acc << bits) | (v as u64 & ((1 << bits) - 1));
        n += bits;
        while n >= 8 {
            n -= 8;
            out.push((acc >> n) as u8);
        }
    }
    if n > 0 {
        out.push((acc << (8 - n)) as u8);
    }
    out
}

#[test]
fn static_decoder_streams_output_instead_of_materialising_it() {
    // Each 52-bit block holds 65535 codes of a single-symbol C table (code
    // 509 = 256-byte match) and a single-symbol position table (distance
    // 1): zero bits per code, ~16.7 MB of output per block. 4096 blocks
    // (~26 KB of input) expand to ~68 GB. The decoder used to decode the
    // whole stream into a Vec at `finish()`, so even a `LimitedDecoder`
    // capped at 1 MiB had to allocate it all (a 208-byte payload already
    // cost 512 MiB) before seeing a byte.
    let block = [
        (16, 0xFFFF),
        (5, 0),
        (5, 0),
        (9, 0),
        (9, 509),
        (4, 0),
        (4, 0),
    ];
    let fields: Vec<(u32, u32)> = block
        .iter()
        .copied()
        .cycle()
        .take(block.len() * 4096)
        .collect();
    let payload = pack_bits(&fields);

    let mut dec = compcol::limit::LimitedDecoder::new(Lh5::decoder(), 1 << 20);
    let mut buf = vec![0u8; 64 * 1024];
    let (p, _) = dec.decode(&payload, &mut buf).unwrap();
    assert_eq!(p.consumed, payload.len());
    let mut total = 0usize;
    let err = loop {
        match dec.finish(&mut buf) {
            Ok((p, status)) => {
                assert!(buf[..p.written].iter().all(|&b| b == b' '));
                total += p.written;
                assert_ne!(status, Status::StreamEnd);
            }
            Err(e) => break e,
        }
    };
    assert_eq!(err, Error::OutputLimitExceeded);
    assert_eq!(total, 1 << 20);
}

// ─── lh2 conformance ─────────────────────────────────────────────────────

/// `M(len, dist)` or a literal, for hand-written token lists.
#[derive(Clone, Copy)]
enum Tok {
    L(u8),
    M(usize, usize),
}

/// Apply tokens to a space-filled 8 KiB history (the lh2 initial window).
fn replay(tokens: &[Tok]) -> Vec<u8> {
    let mut out = vec![b' '; 8192];
    for &t in tokens {
        match t {
            Tok::L(b) => out.push(b),
            Tok::M(len, dist) => {
                for _ in 0..len {
                    out.push(out[out.len() - dist]);
                }
            }
        }
    }
    out.split_off(8192)
}

fn hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

#[test]
fn lh2_decodes_spec_vectors() {
    // Streams checked against the LHa for UNIX decoder, with the token lists
    // that produced them (escapes, matches into the initial spaces, several
    // position-tree insertions at once, a length of 287).
    let lits = |s: &[u8]| s.iter().map(|&b| Tok::L(b)).collect::<Vec<_>>();
    let mut v2 = lits(b"hello ");
    v2.extend([Tok::M(11, 6), Tok::L(10)]);
    let mut v3 = vec![Tok::M(4, 1)];
    v3.extend(lits(b"abc"));
    let v4 = vec![Tok::M(256, 1), Tok::M(44, 1), Tok::L(120)];
    let mut v5 = lits(b"abcdefgh");
    v5.extend([
        Tok::M(57, 8),
        Tok::M(3, 65),
        Tok::M(3, 2),
        Tok::M(40, 100),
        Tok::M(287, 128),
    ]);
    let cases = [
        ("05", lits(b"A")),
        ("2c2930df33f2660bce", v2),
        ("c50094989c", v3),
        ("e1e003843200f0", v4),
        ("25262728292a2b2c25191f1006c01d908c7abfff80", v5),
    ];
    for (stream, tokens) in &cases {
        let want = replay(tokens);
        let stream = hex(stream);
        for &(ic, oc) in &[(1 << 20, 1 << 20), (1, 1), (3, 7)] {
            let dec = Lh2::decoder_with(DecoderConfig::with_len(want.len()));
            assert_eq!(decode_chunked(dec, &stream, ic, oc), want);
        }
    }
    assert_eq!(replay(&cases[1].1), b"hello hello hello\n");
    assert_eq!(replay(&cases[2].1), b"    abc");
}

#[test]
fn lh2_truncated_and_garbage_input_fail_cleanly() {
    let data = lh2_stress_input();
    let payload = encode_chunked(Lh2::encoder(), &data, 1 << 16, 1 << 16);
    for cut in [0, 1, 7, payload.len() / 2, payload.len() - 1] {
        let mut dec = Lh2::decoder_with(DecoderConfig::with_len(data.len()));
        let mut buf = vec![0u8; 4096];
        dec.decode(&payload[..cut], &mut buf).unwrap();
        match dec.finish(&mut buf) {
            // An empty stream is the zero-length payload.
            Ok((p, _)) => assert!(cut == 0 && p.written == 0),
            Err(e) => assert_eq!(e, Error::UnexpectedEnd, "cut at {cut}"),
        }
    }
    for seed in 0..64 {
        let stream = noise(300, seed);
        let mut dec = Lh2::decoder_with(DecoderConfig::with_len(1 << 20));
        let mut buf = vec![0u8; 8192];
        let _ = dec.decode(&stream, &mut buf);
        let mut produced = 0usize;
        while let Ok((p, status)) = dec.finish(&mut buf) {
            produced += p.written;
            assert!(produced <= 1 << 20);
            if matches!(status, Status::StreamEnd) || p.written == 0 {
                break;
            }
        }
    }
}

/// Input that drives lh2 through every part of the format: a long run
/// (escaped lengths up to 256), a block repeated at nearly the full 8 KiB
/// distance, and enough word salad for more than 32768 matches and C-tree
/// symbols, so both trees are rebuilt.
fn lh2_stress_input() -> Vec<u8> {
    let mut data = vec![b'q'; 700];
    for (i, run) in [32, 33, 47, 64, 100, 128, 200, 255, 256, 257]
        .iter()
        .enumerate()
    {
        data.extend(std::iter::repeat_n(b'A' + i as u8, run + 1));
    }
    let block = noise(8000, 7);
    data.extend_from_slice(&block);
    data.extend_from_slice(&noise(150, 8));
    data.extend_from_slice(&block[..1000]);
    let words = [
        "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india",
        "juliett", "kilo", "lima", "mike", "november", "oscar", "papa", "quebec", "romeo",
        "sierra", "tango", "uniform", "victor", "whiskey", "xray", "yankee", "zulu", "one", "two",
        "three", "four", "five", "six",
    ];
    let mut rng = 99u32;
    while data.len() < 600_000 {
        rng = rng.wrapping_mul(1103515245).wrapping_add(12345);
        let r = (rng >> 16) as usize;
        data.extend_from_slice(words[r % words.len()].as_bytes());
        data.push(b" ,.\n"[(r >> 5) % 4]);
    }
    data
}

#[test]
fn roundtrip_lh2_stress() {
    let data = lh2_stress_input();
    for &(ic, oc) in &[(1 << 20, 1 << 20), (4093, 517)] {
        let encoded = encode_chunked(Lh2::encoder(), &data, ic, oc);
        let dec = Lh2::decoder_with(DecoderConfig::with_len(data.len()));
        assert!(decode_chunked(dec, &encoded, ic, oc) == data);
    }
}

#[test]
fn lh2_fixture_decodes() {
    // Written by this crate's encoder from `lh2_fixture_text()` and checked
    // with LHa for UNIX (`lha t` OK, `lha p` identical). The encoder is not
    // required to reproduce it byte for byte.
    let archive = include_bytes!("fixtures/lha/lh2.lzh");
    let member = parse_lzh0(archive);
    assert_eq!(member.method, *b"-lh2-");
    let dec = Lh2::decoder_with(DecoderConfig::with_len(member.original));
    let out = decode_chunked(dec, member.packed, 5, 11);
    assert_eq!(crc16(&out), member.crc);
    assert!(out == lh2_fixture_text());
}

fn lh2_fixture_text() -> Vec<u8> {
    let mut text = Vec::new();
    for i in 0..60u32 {
        text.extend_from_slice(format!("line {i}: the quick brown fox jumps. ").as_bytes());
        if i % 20 == 0 {
            text.extend(std::iter::repeat_n(b'=', 300));
        }
        text.push(b'\n');
    }
    text
}

// ─── level-0 .lzh container (test-side only) ─────────────────────────────

/// CRC-16 as LHA stores it (reflected 0xA001, initial 0).
fn crc16(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xA001
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// A one-member level-0 archive holding `packed` as method `method`.
fn build_lzh0(method: &[u8; 5], name: &[u8], original: &[u8], packed: &[u8]) -> Vec<u8> {
    let mut body = method.to_vec();
    body.extend_from_slice(&(packed.len() as u32).to_le_bytes());
    body.extend_from_slice(&(original.len() as u32).to_le_bytes());
    body.extend_from_slice(&0x5021_0000u32.to_le_bytes()); // 2020-01-01 00:00
    body.extend_from_slice(&[0x20, 0, name.len() as u8]);
    body.extend_from_slice(name);
    body.extend_from_slice(&crc16(original).to_le_bytes());
    let sum = body.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    let mut out = vec![body.len() as u8, sum];
    out.extend_from_slice(&body);
    out.extend_from_slice(packed);
    out.push(0); // end of archive
    out
}

struct Lzh0Member<'a> {
    method: [u8; 5],
    original: usize,
    crc: u16,
    packed: &'a [u8],
}

fn parse_lzh0(a: &[u8]) -> Lzh0Member<'_> {
    let size = a[0] as usize;
    let body = &a[2..2 + size];
    let u32le = |o: usize| u32::from_le_bytes(body[o..o + 4].try_into().unwrap()) as usize;
    let name_len = body[19] as usize;
    Lzh0Member {
        method: body[..5].try_into().unwrap(),
        original: u32le(9),
        crc: u16::from_le_bytes([body[20 + name_len], body[21 + name_len]]),
        packed: &a[2 + size..2 + size + u32le(5)],
    }
}

// ─── LHa for UNIX oracle ─────────────────────────────────────────────────

/// The LHa for UNIX binary: `$COMPCOL_LHA`, else `lha` on PATH if it is LHa
/// for UNIX (other `lha`s, e.g. Lhasa, cannot decode `-lh2-`).
fn lha_oracle() -> Option<std::ffi::OsString> {
    if let Some(path) = std::env::var_os("COMPCOL_LHA") {
        return Some(path);
    }
    let out = std::process::Command::new("lha")
        .arg("--version")
        .output()
        .ok()?;
    let text = [out.stdout, out.stderr].concat();
    String::from_utf8_lossy(&text)
        .contains("LHa for UNIX")
        .then(|| "lha".into())
}

/// Wrap `packed` in a level-0 archive and check that the oracle tests it OK
/// and prints back exactly `original`.
fn oracle_check(lha: &std::ffi::OsStr, method: &[u8; 5], original: &[u8], packed: &[u8]) {
    use std::process::Command;
    let dir = std::env::temp_dir().join(format!(
        "compcol-lha-{}-{}",
        std::process::id(),
        String::from_utf8_lossy(method).trim_matches('-')
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("t.lzh");
    std::fs::write(&path, build_lzh0(method, b"data.bin", original, packed)).unwrap();

    let what = format!(
        "{} ({} bytes)",
        String::from_utf8_lossy(method),
        original.len()
    );
    let test = Command::new(lha).arg("tq").arg(&path).output().unwrap();
    assert!(
        test.status.success(),
        "lha t failed for {what}: {}",
        String::from_utf8_lossy(&test.stderr)
    );
    let print = Command::new(lha).arg("pq").arg(&path).output().unwrap();
    assert!(print.status.success(), "lha p failed for {what}");
    assert!(print.stdout == original, "lha p output differs for {what}");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn oracle_decodes_our_streams() {
    let Some(lha) = lha_oracle() else {
        eprintln!("LHa for UNIX not found (set COMPCOL_LHA); skipping oracle conformance");
        return;
    };
    let mut inputs = sample_inputs();
    inputs.push(lh2_stress_input());
    inputs.push(lh2_fixture_text());
    fn check<A: Algorithm>(lha: &std::ffi::OsStr, method: &[u8; 5], inputs: &[Vec<u8>]) {
        for data in inputs {
            let packed = compcol::vec::compress_to_vec::<A>(data).unwrap();
            oracle_check(lha, method, data, &packed);
        }
    }
    check::<Lh2>(&lha, b"-lh2-", &inputs);
    check::<Lh1>(&lha, b"-lh1-", &inputs);
    check::<Lh4>(&lha, b"-lh4-", &inputs);
    check::<Lh5>(&lha, b"-lh5-", &inputs);
    check::<Lh6>(&lha, b"-lh6-", &inputs);
    check::<Lh7>(&lha, b"-lh7-", &inputs);
}

/// Regenerate `tests/fixtures/lha/lh2.lzh` (then verify it with the oracle):
/// `cargo test --features lha --test lha -- --ignored write_lh2_fixture`.
#[test]
#[ignore]
fn write_lh2_fixture() {
    let text = lh2_fixture_text();
    let packed = compcol::vec::compress_to_vec::<Lh2>(&text).unwrap();
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/lha/lh2.lzh");
    std::fs::create_dir_all(std::path::Path::new(path).parent().unwrap()).unwrap();
    std::fs::write(path, build_lzh0(b"-lh2-", b"lh2.txt", &text, &packed)).unwrap();
}
