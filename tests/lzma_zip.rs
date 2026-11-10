//! ZIP method 14 (LZMA) entry data: `lzma::Decoder::zip` and
//! `lzma::Encoder::zip`.
//!
//! The fixtures under `tests/fixtures/lzma_zip/` were written by 7-Zip
//! (`7zz a -tzip -mm=LZMA`, and `-m0=LZMA -m0eos=off` for entries without
//! the end marker) and by Python's `zipfile` (`ZIP_LZMA`, streamed, so the
//! entries use data descriptors). The ZIP parsing below is a minimal
//! local-header walk for these tests only.
//!
//! Tests that run `7zz` or `python3` skip when the tool is missing.

#![cfg(feature = "lzma")]

use compcol::lzma::{Decoder, DecoderConfig, Encoder, EncoderConfig};
use compcol::{ContiguousDecoder as _, Decoder as _, Encoder as _, Error, Status};

const METHOD_LZMA: u16 = 14;
const GP_EOS: u16 = 0x0002;
const GP_DESCRIPTOR: u16 = 0x0008;

fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn u16_at(d: &[u8], i: usize) -> u16 {
    u16::from_le_bytes([d[i], d[i + 1]])
}

fn u32_at(d: &[u8], i: usize) -> u32 {
    u32::from_le_bytes([d[i], d[i + 1], d[i + 2], d[i + 3]])
}

fn fixture(name: &str) -> Vec<u8> {
    let path = format!(
        "{}/tests/fixtures/lzma_zip/{name}",
        env!("CARGO_MANIFEST_DIR")
    );
    std::fs::read(&path).unwrap_or_else(|e| panic!("{path}: {e}"))
}

/// Feed `input` in `in_chunk` pieces through an `out_chunk` buffer, then
/// `finish`. Returns the output and how many input bytes were consumed.
fn run(
    dec: &mut Decoder,
    input: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Result<(Vec<u8>, usize), Error> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    let mut pos = 0;
    while pos < input.len() {
        let end = (pos + in_chunk).min(input.len());
        let (p, status) = dec.decode(&input[pos..end], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        pos += p.consumed;
        if status == Status::StreamEnd {
            return Ok((out, pos));
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if status == Status::StreamEnd {
            return Ok((out, pos));
        }
        assert!(p.written > 0, "finish made no progress");
    }
}

fn decode_entry(
    data: &[u8],
    gp: u16,
    len: Option<u64>,
    in_chunk: usize,
    out_chunk: usize,
) -> Result<Vec<u8>, Error> {
    let mut dec = Decoder::zip_from_gp_flags(gp, len);
    let (out, consumed) = run(&mut dec, data, in_chunk, out_chunk)?;
    assert_eq!(consumed, data.len(), "entry not fully consumed");
    Ok(out)
}

struct Entry {
    name: String,
    gp: u16,
    method: u16,
    crc: u32,
    size: u64,
    data: Vec<u8>,
}

/// Walk the local file headers. Entries with a data descriptor (sizes not
/// in the local header) are delimited by decoding them with our decoder
/// and taking its exact consumption, so this also checks that.
fn entries(zip: &[u8]) -> Vec<Entry> {
    let mut v = Vec::new();
    let mut i = 0;
    while u32_at(zip, i) == 0x0403_4b50 {
        let gp = u16_at(zip, i + 6);
        let method = u16_at(zip, i + 8);
        let mut crc = u32_at(zip, i + 14);
        let mut csize = u32_at(zip, i + 18) as usize;
        let mut size = u32_at(zip, i + 22) as u64;
        let nlen = u16_at(zip, i + 26) as usize;
        let elen = u16_at(zip, i + 28) as usize;
        let name = String::from_utf8(zip[i + 30..i + 30 + nlen].to_vec()).unwrap();
        let start = i + 30 + nlen + elen;
        if gp & GP_DESCRIPTOR != 0 {
            assert_eq!(method, METHOD_LZMA);
            let mut dec = Decoder::zip_from_gp_flags(gp, None);
            // Give it everything up to the end of the file.
            let (_, consumed) = run(&mut dec, &zip[start..], 1 << 20, 1 << 16).unwrap();
            csize = consumed;
            let mut d = start + csize;
            if u32_at(zip, d) == 0x0807_4b50 {
                d += 4;
            }
            crc = u32_at(zip, d);
            assert_eq!(u32_at(zip, d + 4) as usize, csize, "{name}: csize");
            size = u32_at(zip, d + 8) as u64;
            i = d + 12;
        } else {
            i = start + csize;
        }
        v.push(Entry {
            name,
            gp,
            method,
            crc,
            size,
            data: zip[start..start + csize].to_vec(),
        });
    }
    v
}

fn check_fixture(name: &str, want_eos: bool) {
    let zip = fixture(name);
    let list = entries(&zip);
    assert!(list.iter().any(|e| e.method == METHOD_LZMA), "{name}");
    for e in list.iter().filter(|e| e.method == METHOD_LZMA) {
        let ctx = format!("{name}/{}", e.name);
        assert_eq!(e.gp & GP_EOS != 0, want_eos, "{ctx}: gp {:#x}", e.gp);
        let out = decode_entry(&e.data, e.gp, Some(e.size), 1 << 20, 1 << 16).unwrap();
        assert_eq!(out.len() as u64, e.size, "{ctx}");
        assert_eq!(crc32(&out), e.crc, "{ctx}");
        if want_eos {
            // The marker alone ends the stream.
            let out2 = decode_entry(&e.data, e.gp, None, 1 << 20, 1 << 16).unwrap();
            assert_eq!(out2, out, "{ctx}: no size");
        }
        // Chunked input and output.
        for (ic, oc) in [(1, 1), (1, 4096), (7, 3), (4096, 1), (300, 777)] {
            let got = decode_entry(&e.data, e.gp, Some(e.size), ic, oc).unwrap();
            assert_eq!(got, out, "{ctx}: chunks {ic}/{oc}");
        }
        // Bytes after the entry stay unconsumed.
        let mut tail = e.data.clone();
        tail.extend_from_slice(b"PK\x07\x08 trailing bytes after the entry data");
        for oc in [1 << 16, 100, 1] {
            let mut dec = Decoder::zip_from_gp_flags(e.gp, Some(e.size));
            let (got, consumed) = run(&mut dec, &tail, 1 << 20, oc).unwrap();
            assert_eq!(got, out, "{ctx}: trailing, out {oc}");
            assert_eq!(consumed, e.data.len(), "{ctx}: consumed, out {oc}");
        }
    }
}

#[test]
fn decodes_7zip_entries_with_eos() {
    check_fixture("7z_eos.zip", true);
}

#[test]
fn decodes_7zip_entries_without_eos() {
    check_fixture("7z_noeos.zip", false);
}

#[test]
fn decodes_python_streamed_entries() {
    let zip = fixture("py_stream.zip");
    let list = entries(&zip);
    assert_eq!(list.len(), 2);
    assert!(list.iter().any(|e| e.size == 0), "empty entry");
    for e in &list {
        assert_eq!(e.gp & (GP_EOS | GP_DESCRIPTOR), GP_EOS | GP_DESCRIPTOR);
        let out = decode_entry(&e.data, e.gp, Some(e.size), 1, 1).unwrap();
        assert_eq!(out.len() as u64, e.size, "{}", e.name);
        assert_eq!(crc32(&out), e.crc, "{}", e.name);
    }
}

#[test]
fn marker_rules() {
    let zip = fixture("7z_eos.zip");
    let e = entries(&zip)
        .into_iter()
        .find(|e| e.name == "text.txt")
        .unwrap();
    // A size that disagrees with the marker is an error either way.
    for len in [e.size - 1, e.size + 1, 0] {
        assert!(
            decode_entry(&e.data, GP_EOS, Some(len), 1 << 20, 1 << 16).is_err(),
            "len {len}"
        );
    }
    // Size-only reading of a stream that has a marker: the marker after
    // the size is read too, so consumption stays exact.
    let mut tail = e.data.clone();
    tail.extend_from_slice(&[0xAA; 40]);
    for ic in [1 << 20, 1] {
        let mut dec = Decoder::zip(false, Some(e.size));
        let (out, consumed) = run(&mut dec, &tail, ic, 1 << 16).unwrap();
        assert_eq!(crc32(&out), e.crc);
        if ic > 1 {
            assert_eq!(consumed, e.data.len());
        }
    }

    // Requiring a marker on a stream without one fails.
    let zip = fixture("7z_noeos.zip");
    let e = entries(&zip)
        .into_iter()
        .find(|e| e.name == "text.txt")
        .unwrap();
    assert!(decode_entry(&e.data, GP_EOS, Some(e.size), 1 << 20, 1 << 16).is_err());
    assert!(decode_entry(&e.data, 0, None, 1 << 20, 1 << 16).is_err());
}

#[test]
fn bad_header() {
    let mut d = encode(b"abc", 6, true);
    d[2] = 6; // properties size must be 5
    assert_eq!(
        decode_entry(&d, GP_EOS, Some(3), 64, 64),
        Err(Error::BadHeader)
    );
}

fn encode_chunked(data: &[u8], level: u8, eos: bool, in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::zip(EncoderConfig { level }, eos);
    assert_eq!(enc.eos_marker(), eos);
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk];
    for chunk in data.chunks(in_chunk.max(1)) {
        let mut pos = 0;
        loop {
            let (p, status) = enc.encode(&chunk[pos..], &mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            pos += p.consumed;
            if status == Status::InputEmpty {
                break;
            }
        }
    }
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if status == Status::StreamEnd {
            break;
        }
    }
    out
}

fn encode(data: &[u8], level: u8, eos: bool) -> Vec<u8> {
    encode_chunked(data, level, eos, 1 << 20, 1 << 16)
}

fn sample(n: usize) -> Vec<u8> {
    let mut x = 0x1234_5678u32;
    (0..n)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            if (i / 512) % 2 == 0 {
                b"lorem ipsum dolor sit amet "[i % 27]
            } else {
                (x >> 24) as u8
            }
        })
        .collect()
}

#[test]
fn encoder_header() {
    assert!(Encoder::new().eos_marker());
    let d = encode(b"hello", 6, false);
    assert_eq!(&d[2..5], &[5, 0, 0x5d]);
    assert_eq!(u32_at(&d, 5), 8 << 20);
}

#[test]
fn round_trip() {
    for n in [0usize, 1, 5, 300, 70_000, 300_000] {
        let data = sample(n);
        for level in [0u8, 6, 9] {
            for eos in [true, false] {
                let enc = encode(&data, level, eos);
                let gp = if eos { GP_EOS } else { 0 };
                let ctx = format!("n {n} level {level} eos {eos}");
                let out = decode_entry(&enc, gp, Some(n as u64), 1 << 20, 1 << 16).expect(&ctx);
                assert_eq!(out, data, "{ctx}");
                if eos {
                    let out = decode_entry(&enc, gp, None, 1 << 20, 1 << 16).expect(&ctx);
                    assert_eq!(out, data, "{ctx}: no size");
                }
            }
        }
    }
}

#[test]
fn round_trip_chunked() {
    let data = sample(5000);
    for eos in [true, false] {
        let gp = if eos { GP_EOS } else { 0 };
        let whole = encode(&data, 6, eos);
        for (ic, oc) in [(1, 1), (3, 2), (1, 4096), (4096, 1)] {
            let enc = encode_chunked(&data, 6, eos, ic, oc);
            assert_eq!(enc, whole, "eos {eos} chunks {ic}/{oc}");
            let out = decode_entry(&enc, gp, Some(data.len() as u64), ic, oc).unwrap();
            assert_eq!(out, data, "eos {eos} chunks {ic}/{oc}");
        }
    }
}

#[test]
fn empty_entry() {
    for eos in [true, false] {
        let gp = if eos { GP_EOS } else { 0 };
        let enc = encode(b"", 6, eos);
        let out = decode_entry(&enc, gp, Some(0), 1, 1).unwrap();
        assert!(out.is_empty());
    }
}

#[test]
fn truncation_is_an_error() {
    let data = sample(2000);
    for eos in [true, false] {
        let gp = if eos { GP_EOS } else { 0 };
        let enc = encode(&data, 6, eos);
        for cut in 0..enc.len() {
            let mut dec = Decoder::zip_from_gp_flags(gp, Some(data.len() as u64));
            let r = run(&mut dec, &enc[..cut], 1 << 20, 1 << 16);
            assert!(r.is_err(), "eos {eos} cut {cut}/{}", enc.len());
        }
    }
    let enc = encode(b"", 6, false);
    for cut in 0..enc.len() {
        let mut dec = Decoder::zip(false, Some(0));
        assert!(
            run(&mut dec, &enc[..cut], 64, 64).is_err(),
            "empty cut {cut}"
        );
    }
}

/// Size-only mode: a match that runs past the declared size is corrupt. It
/// used to be cut at the size and reported as a complete stream, while a
/// literal past the size was already an error.
#[test]
fn match_past_declared_size_is_corrupt() {
    // 30 bytes that end inside a match.
    let data = b"abcabcabcabcabcabcabcabcabcabc";
    for eos in [false, true] {
        let enc = encode(data, 6, eos);
        let mut dec = Decoder::zip(false, Some(30));
        assert_eq!(run(&mut dec, &enc, 1 << 20, 1 << 16).unwrap().0, data);
        for len in [29u64, 26, 4] {
            for (ic, oc) in [(1 << 20, 1 << 16), (1, 1), (7, 3)] {
                let mut dec = Decoder::zip(false, Some(len));
                assert_eq!(
                    run(&mut dec, &enc, ic, oc),
                    Err(Error::Corrupt),
                    "eos {eos} len {len} chunks {ic}/{oc}"
                );
            }
        }
    }
}

#[test]
fn reset_keeps_zip_mode() {
    let data = sample(3000);
    let enc = encode(&data, 6, false);
    let mut dec = Decoder::zip(false, Some(data.len() as u64));
    let (a, _) = run(&mut dec, &enc, 1 << 20, 1 << 16).unwrap();
    dec.reset();
    let (b, _) = run(&mut dec, &enc, 17, 33).unwrap();
    assert_eq!(a, data);
    assert_eq!(b, data);

    let mut e = Encoder::zip(EncoderConfig::default(), false);
    let mut buf = vec![0u8; 1 << 16];
    e.encode(&data, &mut buf).unwrap();
    e.reset();
    assert!(!e.eos_marker());
}

/// The ZIP entry points take the same dictionary limit as `.lzma`: the
/// dictionary size in the entry's properties is checked against it.
#[test]
fn zip_max_dict_size() {
    let data = sample(3000);
    let len = Some(data.len() as u64);
    // The dictionary size is bytes 5..9 of the entry (after the 4-byte ZIP
    // LZMA header and the props byte).
    let with_dict = |dict: u32| {
        let mut e = encode(&data, 6, false);
        e[5..9].copy_from_slice(&dict.to_le_bytes());
        e
    };
    let cfg = |max: u64| DecoderConfig::with_max_dict_size(max);

    // Default: 64 MiB, as for `.lzma`.
    assert_eq!(Decoder::zip(false, len).max_dict_size(), 64 << 20);
    let mut dec = Decoder::zip(false, len);
    assert_eq!(
        run(&mut dec, &with_dict(64 << 20), 4096, 4096).unwrap().0,
        data
    );
    for mut dec in [
        Decoder::zip(false, len),
        Decoder::zip_from_gp_flags(0, len),
        Decoder::zip_with_config(false, len, DecoderConfig::default()),
    ] {
        assert_eq!(
            run(&mut dec, &with_dict((64 << 20) + 1), 4096, 4096),
            Err(Error::Unsupported)
        );
    }

    // Configured, lower and higher than the default, by either spelling.
    for max in [1u32 << 20, 1 << 30] {
        for (dict, ok) in [(max - 1, true), (max, true), (max + 1, false)] {
            for mut dec in [
                Decoder::zip_with_config(false, len, cfg(max as u64)),
                Decoder::zip(false, len).with_max_dict_size(max as u64),
                Decoder::zip_from_gp_flags(0, len).with_max_dict_size(max as u64),
            ] {
                assert_eq!(dec.max_dict_size(), max as u64);
                let got = run(&mut dec, &with_dict(dict), 4096, 4096);
                if ok {
                    assert_eq!(got.unwrap().0, data, "max {max} dict {dict}");
                    // A declared gigabyte costs what the entry produces.
                    assert!(dec.dict_allocated() <= 8192, "{}", dec.dict_allocated());
                } else {
                    assert_eq!(got, Err(Error::Unsupported), "max {max} dict {dict}");
                    assert_eq!(dec.dict_allocated(), 0);
                }
            }
        }
    }

    // `reset` keeps the limit along with the ZIP settings.
    let mut dec = Decoder::zip(false, len).with_max_dict_size(1 << 20);
    assert_eq!(
        run(&mut dec, &with_dict(1 << 21), 4096, 4096),
        Err(Error::Unsupported)
    );
    dec.reset();
    assert_eq!(dec.max_dict_size(), 1 << 20);
    assert_eq!(run(&mut dec, &with_dict(1 << 20), 17, 33).unwrap().0, data);
}

// ─── external tools ────────────────────────────────────────────────────

/// Minimal single-entry ZIP (no data descriptor) around method-14 data.
fn write_zip(name: &str, data: &[u8], compressed: &[u8], gp: u16) -> Vec<u8> {
    let crc = crc32(data);
    let mut z = Vec::new();
    let local = |z: &mut Vec<u8>| {
        z.extend_from_slice(&0x0403_4b50u32.to_le_bytes());
        z.extend_from_slice(&63u16.to_le_bytes()); // version needed 6.3
        z.extend_from_slice(&gp.to_le_bytes());
        z.extend_from_slice(&METHOD_LZMA.to_le_bytes());
        z.extend_from_slice(&[0, 0, 0x21, 0]); // time, date (1980-01-01)
        z.extend_from_slice(&crc.to_le_bytes());
        z.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
        z.extend_from_slice(&(data.len() as u32).to_le_bytes());
        z.extend_from_slice(&(name.len() as u16).to_le_bytes());
        z.extend_from_slice(&0u16.to_le_bytes());
    };
    local(&mut z);
    z.extend_from_slice(name.as_bytes());
    z.extend_from_slice(compressed);
    let cd = z.len();
    z.extend_from_slice(&0x0201_4b50u32.to_le_bytes());
    z.extend_from_slice(&63u16.to_le_bytes()); // version made by
    let mut h = Vec::new();
    local(&mut h);
    z.extend_from_slice(&h[4..]); // same fields as the local header
    z.extend_from_slice(&[0; 6]); // comment len, disk, int attr
    z.extend_from_slice(&[0; 4]); // ext attr
    z.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    z.extend_from_slice(name.as_bytes());
    let cd_len = z.len() - cd;
    z.extend_from_slice(&0x0605_4b50u32.to_le_bytes());
    z.extend_from_slice(&[0; 4]);
    z.extend_from_slice(&1u16.to_le_bytes());
    z.extend_from_slice(&1u16.to_le_bytes());
    z.extend_from_slice(&(cd_len as u32).to_le_bytes());
    z.extend_from_slice(&(cd as u32).to_le_bytes());
    z.extend_from_slice(&0u16.to_le_bytes());
    z
}

fn tool(cmd: &str) -> bool {
    std::process::Command::new(cmd)
        .arg("--help")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok()
}

fn sevenzip() -> Option<&'static str> {
    ["7zz", "7z"].into_iter().find(|c| tool(c))
}

fn temp_dir(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("compcol-lzma-zip-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const PY_EXTRACT: &str = r#"
import sys, zipfile
with zipfile.ZipFile(sys.argv[1]) as z:
    sys.stdout.buffer.write(z.read(z.namelist()[0]))
"#;

#[test]
fn our_entries_extract_with_7zip_and_python() {
    let seven = sevenzip();
    let python = tool("python3");
    if seven.is_none() && !python {
        eprintln!("7zz/7z and python3 not available; skipping");
        return;
    }
    let dir = temp_dir("enc");
    for n in [0usize, 1, 4000, 200_000] {
        let data = sample(n);
        for eos in [true, false] {
            let enc = Encoder::zip(EncoderConfig::default(), eos);
            let gp = if enc.eos_marker() { GP_EOS } else { 0 };
            let comp = encode(&data, 6, eos);
            let zip = write_zip("f.bin", &data, &comp, gp);
            let path = dir.join(format!("ours-{n}-{eos}.zip"));
            std::fs::write(&path, &zip).unwrap();
            if let Some(seven) = seven {
                let st = std::process::Command::new(seven)
                    .arg("t")
                    .arg(&path)
                    .stdout(std::process::Stdio::null())
                    .status()
                    .unwrap();
                assert!(st.success(), "7z t: n {n} eos {eos}");
                let out = std::process::Command::new(seven)
                    .args(["x", "-so"])
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(out.status.success(), "7z x: n {n} eos {eos}");
                assert_eq!(out.stdout, data, "7z x: n {n} eos {eos}");
            }
            if python {
                let out = std::process::Command::new("python3")
                    .args(["-I", "-c", PY_EXTRACT])
                    .arg(&path)
                    .output()
                    .unwrap();
                assert!(out.status.success(), "python: n {n} eos {eos}");
                assert_eq!(out.stdout, data, "python: n {n} eos {eos}");
            }
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

const PY_WRITE: &str = r#"
import sys, zipfile
data = open(sys.argv[2], "rb").read()
with zipfile.ZipFile(sys.argv[1], "w", compression=zipfile.ZIP_LZMA) as z:
    z.writestr("f.bin", data)
"#;

#[test]
fn decodes_fresh_7zip_and_python_entries() {
    let seven = sevenzip();
    let python = tool("python3");
    if seven.is_none() && !python {
        eprintln!("7zz/7z and python3 not available; skipping");
        return;
    }
    let dir = temp_dir("dec");
    for n in [1usize, 4000, 200_000] {
        let data = sample(n);
        let src = dir.join("f.bin");
        std::fs::write(&src, &data).unwrap();
        let mut zips = Vec::new();
        if let Some(seven) = seven {
            for (tag, args) in [
                ("eos", &["-mm=LZMA"][..]),
                ("noeos", &["-m0=LZMA", "-m0eos=off"][..]),
                ("mx9", &["-mm=LZMA", "-mx=9"][..]),
            ] {
                let path = dir.join(format!("7z-{n}-{tag}.zip"));
                let st = std::process::Command::new(seven)
                    .args(["a", "-tzip"])
                    .args(args)
                    .arg(&path)
                    .arg(&src)
                    .stdout(std::process::Stdio::null())
                    .status()
                    .unwrap();
                assert!(st.success());
                zips.push(path);
            }
        }
        if python {
            let path = dir.join(format!("py-{n}.zip"));
            let st = std::process::Command::new("python3")
                .args(["-I", "-c", PY_WRITE])
                .arg(&path)
                .arg(&src)
                .status()
                .unwrap();
            assert!(st.success());
            zips.push(path);
        }
        for path in zips {
            let zip = std::fs::read(&path).unwrap();
            let list = entries(&zip);
            assert_eq!(list.len(), 1);
            let e = &list[0];
            if e.method != METHOD_LZMA {
                continue; // stored: too small to compress
            }
            let out = decode_entry(&e.data, e.gp, Some(e.size), 1 << 20, 1 << 16).unwrap();
            assert_eq!(out, data, "{}", path.display());
            let out = decode_entry(&e.data, e.gp, Some(e.size), 1, 7).unwrap();
            assert_eq!(out, data, "{} chunked", path.display());
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

// ─── contiguous output (ContiguousDecoder) ───────────────────────────────
//
// The ZIP modes through `decode_contiguous` / `finish_contiguous`: the
// caller's buffer is the history, no dictionary is allocated, and the
// marker / size rules and the errors are those of `decode` / `finish`.

/// Like `run`, on the contiguous path. The buffer starts `start` bytes
/// long; on `OutputFull` a new one `step` bytes longer replaces it (the
/// old one is scribbled on first). `step == 0`: it must be big enough.
fn run_contiguous(
    dec: &mut Decoder,
    input: &[u8],
    in_chunk: usize,
    start: usize,
    step: usize,
) -> Result<(Vec<u8>, usize), Error> {
    fn grow(out: &mut Vec<u8>, filled: usize, step: usize) {
        assert_eq!(filled, out.len(), "OutputFull with room left");
        assert!(step > 0, "OutputFull with a buffer that should be enough");
        let mut bigger = vec![0xA5u8; out.len() + step];
        bigger[..filled].copy_from_slice(&out[..filled]);
        out.fill(0x5A);
        *out = bigger;
    }
    let mut out = vec![0xA5u8; start];
    let mut filled = 0;
    let mut pos = 0;
    while pos < input.len() {
        let end = (pos + in_chunk).min(input.len());
        let (p, status) = dec.decode_contiguous(&input[pos..end], &mut out, filled)?;
        pos += p.consumed;
        filled += p.written;
        match status {
            Status::StreamEnd => {
                out.truncate(filled);
                return Ok((out, pos));
            }
            Status::OutputFull => grow(&mut out, filled, step),
            Status::InputEmpty => assert_eq!(pos, end, "InputEmpty with input left"),
        }
    }
    loop {
        let (p, status) = dec.finish_contiguous(&mut out, filled)?;
        filled += p.written;
        if status == Status::StreamEnd {
            out.truncate(filled);
            return Ok((out, pos));
        }
        grow(&mut out, filled, step);
    }
}

/// Decode `input` with `make`'s decoders on both paths, several ways of
/// feeding and growing, and check that they agree. `n` is the decoded size
/// to plan buffers with. Returns the windowed result.
fn both_paths(
    make: &dyn Fn() -> Decoder,
    input: &[u8],
    n: usize,
    ctx: &str,
) -> Result<(Vec<u8>, usize), Error> {
    let whole = input.len().max(1);
    let want = run(&mut make(), input, whole, 1 << 16);
    let mut shapes = vec![
        (whole, n, 0),
        (whole, n + 100, 0),
        (whole, 0, n / 9 + 1),
        (300, n / 2, n / 4 + 7),
    ];
    if n <= 4096 {
        shapes.extend([(1, 0, 1), (1, n, 0), (7, 3, 5)]);
    }
    for (in_chunk, start, step) in shapes {
        let ctx = format!("{ctx}: in {in_chunk}, buffer {start}+{step}");
        // The error of a stream fed in pieces is compared with the
        // windowed path fed the same way; a good stream's output and
        // consumption with the one-piece reference.
        let want = match &want {
            Err(_) if in_chunk < whole => run(&mut make(), input, in_chunk, 1 << 16),
            w => w.clone(),
        };
        let mut dec = make();
        let got = run_contiguous(&mut dec, input, in_chunk, start, step);
        assert_eq!(dec.dict_allocated(), 0, "{ctx}: dictionary allocated");
        match (&got, &want) {
            (Ok((g, gc)), Ok((w, wc))) => {
                assert!(g == w, "{ctx}: output differs");
                if in_chunk >= whole {
                    assert_eq!(gc, wc, "{ctx}: consumed");
                } else {
                    // Small pieces: up to a packet's lookahead may have
                    // been taken past the end by earlier calls.
                    assert!(*gc >= *wc && *gc <= *wc + 20, "{ctx}: consumed {gc}/{wc}");
                }
            }
            (Err(g), Err(w)) => assert_eq!(g, w, "{ctx}"),
            _ => panic!(
                "{ctx}: contiguous {:?}, windowed {:?}",
                got.as_ref().map(|r| r.0.len()),
                want.as_ref().map(|r| r.0.len())
            ),
        }
    }
    want
}

/// Entries written by 7-Zip and Python decode the same on both paths,
/// with the size, without it (marker only), and with bytes after them.
#[test]
fn contiguous_decodes_fixture_entries() {
    for name in ["7z_eos.zip", "7z_noeos.zip", "py_stream.zip"] {
        let zip = fixture(name);
        for e in entries(&zip).iter().filter(|e| e.method == METHOD_LZMA) {
            let ctx = format!("{name}/{}", e.name);
            let n = e.size as usize;
            let mut tail = e.data.clone();
            tail.extend_from_slice(b"PK\x07\x08 trailing bytes after the entry data");
            let mut lens = vec![Some(e.size)];
            if e.gp & GP_EOS != 0 {
                lens.push(None);
            }
            for len in lens {
                for input in [&e.data, &tail] {
                    let make = || Decoder::zip_from_gp_flags(e.gp, len);
                    let (out, consumed) = both_paths(&make, input, n, &ctx).unwrap();
                    assert_eq!(out.len(), n, "{ctx}");
                    assert_eq!(crc32(&out), e.crc, "{ctx}");
                    assert_eq!(consumed, e.data.len(), "{ctx}");
                }
            }
        }
    }
}

/// Our own entries, with and without the marker, read every way the
/// decoder allows.
#[test]
fn contiguous_round_trip() {
    for n in [0usize, 1, 2, 100, 3000, 40_000] {
        let data = sample(n);
        for level in [0u8, 6] {
            for eos in [true, false] {
                let enc = encode(&data, level, eos);
                let size = Some(n as u64);
                // (marker flag, size) the entry can be read with.
                let mut modes = vec![(eos, size), (false, size)];
                if eos {
                    modes.push((true, None));
                    modes.push((false, None));
                }
                for (flag, len) in modes {
                    let ctx = format!("n {n} level {level} eos {eos} as {flag}/{len:?}");
                    let make = || Decoder::zip(flag, len);
                    let (out, consumed) = both_paths(&make, &enc, n, &ctx).unwrap();
                    assert!(out == data, "{ctx}");
                    assert_eq!(consumed, enc.len(), "{ctx}");
                }
            }
        }
    }
}

/// An exact-size buffer never sees `OutputFull`, marker or not.
#[test]
fn contiguous_exact_size_buffer() {
    let data = sample(5000);
    for eos in [true, false] {
        let enc = encode(&data, 6, eos);
        for in_chunk in [enc.len(), 1, 33] {
            let mut dec = Decoder::zip(eos, Some(data.len() as u64));
            let mut out = vec![0u8; data.len()];
            let (mut filled, mut pos) = (0, 0);
            let mut ended = false;
            while pos < enc.len() && !ended {
                let end = (pos + in_chunk).min(enc.len());
                let (p, status) = dec
                    .decode_contiguous(&enc[pos..end], &mut out, filled)
                    .unwrap();
                pos += p.consumed;
                filled += p.written;
                assert_ne!(status, Status::OutputFull, "eos {eos} in {in_chunk}");
                ended = status == Status::StreamEnd;
            }
            if !ended {
                let (p, status) = dec.finish_contiguous(&mut out, filled).unwrap();
                filled += p.written;
                assert_eq!(status, Status::StreamEnd, "eos {eos} in {in_chunk}");
            }
            assert_eq!((pos, filled), (enc.len(), data.len()));
            assert!(out == data);
        }
    }
}

/// What the windowed path rejects, the contiguous one rejects the same
/// way: truncation, marker and size disagreements, bad headers.
#[test]
fn contiguous_errors_match_windowed() {
    let data = sample(2000);
    let n = data.len() as u64;

    // Truncation at every length.
    let short = sample(700);
    for eos in [true, false] {
        let enc = encode(&short, 6, eos);
        for cut in 0..enc.len() {
            let ctx = format!("eos {eos} cut {cut}/{}", enc.len());
            let make = || Decoder::zip(eos, Some(short.len() as u64));
            let r = both_paths(&make, &enc[..cut], short.len(), &ctx);
            assert_eq!(r, Err(Error::UnexpectedEnd), "{ctx}");
        }
    }
    let enc = encode(b"", 6, false);
    for cut in 0..enc.len() {
        let make = || Decoder::zip(false, Some(0));
        assert!(
            both_paths(&make, &enc[..cut], 0, "empty").is_err(),
            "cut {cut}"
        );
    }

    // The marker and the size must agree.
    let with_eos = encode(&data, 6, true);
    let without = encode(&data, 6, false);
    for len in [n - 1, n + 1, 0] {
        for (flag, enc) in [(true, &with_eos), (false, &with_eos), (false, &without)] {
            let ctx = format!("len {len} flag {flag}");
            let make = || Decoder::zip(flag, Some(len));
            assert!(
                both_paths(&make, enc, data.len() + 1, &ctx).is_err(),
                "{ctx}"
            );
        }
    }
    // A marker required, or the only way to end, on a stream without one.
    for len in [Some(n), None] {
        let make = || Decoder::zip(true, len);
        assert!(both_paths(&make, &without, data.len(), "no marker").is_err());
    }
    let make = || Decoder::zip(false, None);
    assert!(both_paths(&make, &without, data.len(), "no marker, no size").is_err());

    // A match running over the declared size.
    let abc = b"abcabcabcabcabcabcabcabcabcabc";
    for eos in [false, true] {
        let enc = encode(abc, 6, eos);
        for len in [29u64, 26, 4] {
            let make = || Decoder::zip(false, Some(len));
            let ctx = format!("eos {eos} len {len}");
            assert_eq!(
                both_paths(&make, &enc, 30, &ctx),
                Err(Error::Corrupt),
                "{ctx}"
            );
        }
    }

    // Header: properties size, properties byte, range-coder first byte.
    for (at, value, want) in [
        (2usize, 6u8, Error::BadHeader),
        (4, 225, Error::BadHeader),
        (9, 1, Error::Corrupt),
    ] {
        let mut enc = encode(b"abc", 6, true);
        enc[at] = value;
        let make = || Decoder::zip(true, Some(3));
        assert_eq!(both_paths(&make, &enc, 3, "header"), Err(want), "byte {at}");
    }
}

/// The dictionary size in the properties is not checked against
/// `max_dict_size` on the contiguous path — there is no dictionary to
/// budget for — but it still bounds how far back a match may reach.
#[test]
fn contiguous_ignores_max_dict_size_and_keeps_the_distance_rule() {
    // 6 KiB of noise twice: the second copy is matches at distance 6144.
    let mut data: Vec<u8> = sample(12 * 1024)
        .chunks(512)
        .skip(1)
        .step_by(2)
        .flatten()
        .copied()
        .collect();
    data.extend_from_within(..);
    assert_eq!(data.len(), 12 * 1024);
    let enc = encode(&data, 6, false);
    assert!(enc.len() < 7 * 1024, "second half must be matches");
    let size = Some(data.len() as u64);
    let with_dict = |dict: u32| {
        let mut e = enc.clone();
        e[5..9].copy_from_slice(&dict.to_le_bytes());
        e
    };

    for dict in [1u32 << 30, u32::MAX] {
        let e = with_dict(dict);
        // Refused by the windowed path under the default limit …
        let mut dec = Decoder::zip(false, size);
        assert_eq!(run(&mut dec, &e, 1 << 20, 1 << 16), Err(Error::Unsupported));
        // … decoded by the contiguous one, even with the smallest limit.
        for limit in [0, 64 << 20] {
            let mut dec = Decoder::zip(false, size).with_max_dict_size(limit);
            let (out, consumed) = run_contiguous(&mut dec, &e, 500, 10, 1000).unwrap();
            assert!(out == data, "dict {dict} limit {limit}");
            assert_eq!(consumed, e.len());
            assert_eq!(dec.dict_allocated(), 0);
        }
    }
    // A dictionary smaller than the distance: corrupt on both paths.
    for dict in [0u32, 4096, 6143] {
        let e = with_dict(dict);
        let make = || Decoder::zip(false, size);
        let ctx = format!("dict {dict}");
        assert_eq!(
            both_paths(&make, &e, data.len(), &ctx),
            Err(Error::Corrupt),
            "{ctx}"
        );
    }
    let e = with_dict(6144);
    let make = || Decoder::zip(false, size);
    assert!(both_paths(&make, &e, data.len(), "dict 6144").unwrap().0 == data);
}

/// One path per stream; `reset` keeps the ZIP settings and allows either.
#[test]
fn contiguous_and_windowed_calls_do_not_mix() {
    let data = sample(3000);
    let enc = encode(&data, 6, true);
    let mut dec = Decoder::zip(true, Some(data.len() as u64));
    let mut out = vec![0u8; 64];
    let mut scratch = vec![0u8; 4096];

    let (p, status) = dec.decode_contiguous(&enc, &mut out, 0).unwrap();
    assert_eq!((p.written, status), (64, Status::OutputFull));
    assert_eq!(
        dec.decode(&enc[p.consumed..], &mut scratch),
        Err(Error::Unsupported)
    );
    assert_eq!(dec.finish(&mut scratch), Err(Error::Unsupported));
    assert_eq!(
        dec.decode_contiguous(&enc[p.consumed..], &mut out, 63),
        Err(Error::Unsupported)
    );
    assert_eq!(dec.finish_contiguous(&mut out, 65), Err(Error::Unsupported));

    dec.reset();
    let (got, consumed) = run(&mut dec, &enc, 100, 100).unwrap();
    assert_eq!((got, consumed), (data.clone(), enc.len()));
    assert_eq!(
        dec.decode_contiguous(&enc, &mut out, 0),
        Err(Error::Unsupported)
    );
    assert_eq!(dec.finish_contiguous(&mut out, 0), Err(Error::Unsupported));

    dec.reset();
    let (got, consumed) = run_contiguous(&mut dec, &enc, 100, 0, 700).unwrap();
    assert_eq!((got, consumed), (data, enc.len()));
}
