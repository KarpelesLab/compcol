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

use compcol::lzma::{Decoder, Encoder, EncoderConfig};
use compcol::{Decoder as _, Encoder as _, Error, Status};

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
