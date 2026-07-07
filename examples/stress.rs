//! Large-file streaming stress test — bounded memory at any scale.
//!
//! Generates up to many GiB of deterministic data, streams it through an
//! encoder and (interleaved) a decoder, and checks the decoded stream hashes
//! and lengths identically to the input. Holds only fixed-size buffers, so it
//! runs at 16 GiB+ without buffering the whole stream.
//!
//! Usage:
//!   stress <algo> <kind> <total_bytes> <mode>
//!     kind:  text | random | mixed | runs | seq
//!     mode:  self        our encode -> our decode (round-trip hash check)
//!            enc-native  our encode -> native `xz -d` (xz/lzma2 only)
//!            dec-native  native `xz -z` -> our decode (xz only)
//!
//! Exit code 0 = OK, 1 = MISMATCH/error.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::time::Instant;

use compcol::{Status, factory};

// ─── deterministic, position-addressable data generator ──────────────────
// `fill(kind, abs_offset, buf)` fills `buf` with the bytes of the stream at
// absolute offset `abs_offset`, so any range is reproducible (needed to hash
// the input independently of how it is chunked, and for the native modes).

const LOREM: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim ad \
minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea. ";

#[inline]
fn lcg(state: &mut u64) -> u64 {
    // 64-bit LCG (Knuth MMIX constants).
    *state = state
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    *state
}

fn fill(kind: &str, abs: u64, buf: &mut [u8]) {
    match kind {
        "text" => {
            for (i, b) in buf.iter_mut().enumerate() {
                let p = (abs + i as u64) % LOREM.len() as u64;
                *b = LOREM[p as usize];
            }
        }
        "seq" => {
            for (i, b) in buf.iter_mut().enumerate() {
                *b = (abs + i as u64) as u8;
            }
        }
        "random" => {
            // Seed the LCG from the absolute offset so each byte is a pure
            // function of its position (streams reproducibly, still looks
            // incompressible).
            for (i, b) in buf.iter_mut().enumerate() {
                let pos = abs + i as u64;
                let mut s = pos.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xD1B54A32D192ED03;
                s = lcg(&mut s);
                *b = (s >> 33) as u8;
            }
        }
        "runs" => {
            // Long runs of a byte value that changes every ~4 KiB — stresses
            // RLE / overlap copies and offset==1 splats at scale.
            for (i, b) in buf.iter_mut().enumerate() {
                let pos = abs + i as u64;
                *b = (pos >> 12) as u8;
            }
        }
        "mixed" => {
            // Alternate 64 KiB compressible (text) and 64 KiB incompressible
            // (random) blocks — repeatedly crosses the compressed/uncompressed
            // chunk transition the lzma2 encoder switches on.
            for (i, b) in buf.iter_mut().enumerate() {
                let pos = abs + i as u64;
                if (pos >> 16) & 1 == 0 {
                    *b = LOREM[(pos % LOREM.len() as u64) as usize];
                } else {
                    let mut s = pos.wrapping_mul(0x9E3779B97F4A7C15) ^ 0xD1B54A32D192ED03;
                    s = lcg(&mut s);
                    *b = (s >> 33) as u8;
                }
            }
        }
        _ => panic!("unknown kind {kind}"),
    }
}

// ─── rolling 128-bit hash (two independent FNV-1a lanes) ──────────────────
#[derive(Clone, Copy)]
struct Hash {
    a: u64,
    b: u64,
    len: u64,
}
impl Hash {
    fn new() -> Self {
        Self {
            a: 0xcbf29ce484222325,
            b: 0x100000001b3 ^ 0x9E3779B97F4A7C15,
            len: 0,
        }
    }
    #[inline]
    fn update(&mut self, data: &[u8]) {
        let mut a = self.a;
        let mut b = self.b;
        for &x in data {
            a = (a ^ x as u64).wrapping_mul(0x100000001b3);
            b = (b ^ x as u64)
                .wrapping_mul(0x9E3779B97F4A7C15)
                .rotate_left(27);
        }
        self.a = a;
        self.b = b;
        self.len += data.len() as u64;
    }
    fn eq(&self, o: &Hash) -> bool {
        self.a == o.a && self.b == o.b && self.len == o.len
    }
    fn show(&self) -> String {
        format!("{:016x}{:016x}/{}", self.a, self.b, self.len)
    }
}

const CHUNK: usize = 1 << 20; // 1 MiB generator chunk
const BUF: usize = 1 << 18; // 256 KiB codec buffers

fn mb(bytes: u64) -> f64 {
    bytes as f64 / 1e6
}

fn run_self(algo: &str, kind: &str, total: u64) -> Result<(), String> {
    let mut enc = factory::encoder_by_name(algo).ok_or("unknown algo (encode)")?;
    let mut dec = factory::decoder_by_name(algo).ok_or("unknown algo (decode)")?;
    let mut hin = Hash::new();
    let mut hout = Hash::new();
    let mut comp_bytes: u64 = 0;
    let mut enc_buf = vec![0u8; BUF];
    let mut dec_buf = vec![0u8; BUF];
    let mut genbuf = vec![0u8; CHUNK];

    // Feed compressed bytes straight into the decoder, hashing decoded output.
    let feed = |dec: &mut Box<dyn compcol::Decoder>,
                comp: &[u8],
                hout: &mut Hash,
                dec_buf: &mut [u8]|
     -> Result<(), String> {
        let mut c = 0;
        while c < comp.len() {
            let (p, status) = dec
                .decode(&comp[c..], dec_buf)
                .map_err(|e| format!("decode: {e}"))?;
            c += p.consumed;
            hout.update(&dec_buf[..p.written]);
            match status {
                Status::InputEmpty | Status::StreamEnd => {
                    if p.consumed == 0 && p.written == 0 {
                        break;
                    }
                }
                Status::OutputFull => {}
            }
        }
        Ok(())
    };

    let t0 = Instant::now();
    let mut produced: u64 = 0;
    let mut next_report = 1u64 << 30;
    while produced < total {
        let n = CHUNK.min((total - produced) as usize);
        fill(kind, produced, &mut genbuf[..n]);
        hin.update(&genbuf[..n]);
        let mut consumed = 0;
        while consumed < n {
            let (p, status) = enc
                .encode(&genbuf[consumed..n], &mut enc_buf)
                .map_err(|e| format!("encode: {e}"))?;
            consumed += p.consumed;
            comp_bytes += p.written as u64;
            feed(&mut dec, &enc_buf[..p.written], &mut hout, &mut dec_buf)?;
            match status {
                Status::InputEmpty | Status::StreamEnd => {
                    if p.consumed == 0 && p.written == 0 {
                        break;
                    }
                }
                Status::OutputFull => {}
            }
        }
        produced += n as u64;
        if produced >= next_report {
            let s = t0.elapsed().as_secs_f64();
            eprintln!(
                "  .. {} GiB in, {:.1} MB comp, {:.0} MB/s",
                produced >> 30,
                mb(comp_bytes),
                mb(produced) / s
            );
            next_report += 1 << 30;
        }
    }
    // Flush encoder, feeding the tail into the decoder.
    loop {
        let (p, status) = enc
            .finish(&mut enc_buf)
            .map_err(|e| format!("finish enc: {e}"))?;
        comp_bytes += p.written as u64;
        feed(&mut dec, &enc_buf[..p.written], &mut hout, &mut dec_buf)?;
        if matches!(status, Status::StreamEnd) {
            break;
        }
        if p.written == 0 {
            break;
        }
    }
    // Drain any decoder-buffered output, then finish it.
    loop {
        let (p, _s) = dec
            .decode(&[], &mut dec_buf)
            .map_err(|e| format!("drain dec: {e}"))?;
        hout.update(&dec_buf[..p.written]);
        if p.written == 0 {
            break;
        }
    }
    loop {
        let (p, status) = dec
            .finish(&mut dec_buf)
            .map_err(|e| format!("finish dec: {e}"))?;
        hout.update(&dec_buf[..p.written]);
        if matches!(status, Status::StreamEnd) || p.written == 0 {
            break;
        }
    }

    let s = t0.elapsed().as_secs_f64();
    let ok = hin.eq(&hout);
    println!(
        "{algo} {kind} {}B  comp={}B ratio={:.4}  {:.0} MB/s  {}",
        total,
        comp_bytes,
        comp_bytes as f64 / total as f64,
        mb(total) / s,
        if ok { "OK" } else { "MISMATCH" }
    );
    if !ok {
        println!("  in ={}", hin.show());
        println!("  out={}", hout.show());
        return Err(format!(
            "ROUND-TRIP MISMATCH: in.len={} out.len={}",
            hin.len, hout.len
        ));
    }
    Ok(())
}

// Our encode piped to native `xz -d`; verify its output hashes to the input.
fn run_enc_native(algo: &str, kind: &str, total: u64) -> Result<(), String> {
    if algo != "xz" {
        return Err("enc-native only supports xz".into());
    }
    let mut hin = Hash::new();
    let mut genbuf = vec![0u8; CHUNK];
    let mut produced = 0u64;
    while produced < total {
        let n = CHUNK.min((total - produced) as usize);
        fill(kind, produced, &mut genbuf[..n]);
        hin.update(&genbuf[..n]);
        produced += n as u64;
    }

    let mut child = Command::new("xz")
        .args(["-d", "-c", "-T", "1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("spawn xz: {e}"))?;
    let mut xz_in = child.stdin.take().unwrap();
    let mut xz_out = child.stdout.take().unwrap();

    // Thread: generate + our-encode, write compressed to xz stdin.
    let algo_t = algo.to_string();
    let kind_s = kind.to_string();
    let writer = std::thread::spawn(move || -> Result<u64, String> {
        let mut enc = factory::encoder_by_name(&algo_t).ok_or("unknown algo")?;
        let mut enc_buf = vec![0u8; BUF];
        let mut genbuf = vec![0u8; CHUNK];
        let mut comp = 0u64;
        let mut produced = 0u64;
        while produced < total {
            let n = CHUNK.min((total - produced) as usize);
            fill(&kind_s, produced, &mut genbuf[..n]);
            let mut consumed = 0;
            while consumed < n {
                let (p, status) = enc
                    .encode(&genbuf[consumed..n], &mut enc_buf)
                    .map_err(|e| format!("encode: {e}"))?;
                consumed += p.consumed;
                comp += p.written as u64;
                xz_in
                    .write_all(&enc_buf[..p.written])
                    .map_err(|e| format!("pipe: {e}"))?;
                if matches!(status, Status::InputEmpty | Status::StreamEnd)
                    && p.consumed == 0
                    && p.written == 0
                {
                    break;
                }
            }
            produced += n as u64;
        }
        loop {
            let (p, status) = enc
                .finish(&mut enc_buf)
                .map_err(|e| format!("finish: {e}"))?;
            comp += p.written as u64;
            xz_in
                .write_all(&enc_buf[..p.written])
                .map_err(|e| format!("pipe: {e}"))?;
            if matches!(status, Status::StreamEnd) || p.written == 0 {
                break;
            }
        }
        drop(xz_in);
        Ok(comp)
    });

    // Main: hash xz's decompressed output.
    let mut hout = Hash::new();
    let mut rbuf = vec![0u8; BUF];
    loop {
        let k = xz_out
            .read(&mut rbuf)
            .map_err(|e| format!("read xz: {e}"))?;
        if k == 0 {
            break;
        }
        hout.update(&rbuf[..k]);
    }
    let comp = writer.join().map_err(|_| "writer panicked")??;
    let status = child.wait().map_err(|e| format!("wait xz: {e}"))?;
    if !status.success() {
        return Err("native xz -d rejected our output".into());
    }
    let ok = hin.eq(&hout);
    println!(
        "{algo} {kind} {}B (our-enc -> native xz -d)  comp={}B  {}",
        total,
        comp,
        if ok { "OK" } else { "MISMATCH" }
    );
    if !ok {
        return Err(format!("MISMATCH: in.len={} out.len={}", hin.len, hout.len));
    }
    Ok(())
}

fn main() {
    let a: Vec<String> = std::env::args().collect();
    if a.len() < 5 {
        eprintln!(
            "usage: stress <algo> <text|random|mixed|runs|seq> <total_bytes> <self|enc-native>"
        );
        std::process::exit(2);
    }
    let (algo, kind, mode) = (&a[1], &a[2], &a[4]);
    let total: u64 = a[3].parse().expect("total_bytes");
    let r = match mode.as_str() {
        "self" => run_self(algo, kind, total),
        "enc-native" => run_enc_native(algo, kind, total),
        _ => Err(format!("unknown mode {mode}")),
    };
    if let Err(e) = r {
        eprintln!("FAIL: {e}");
        std::process::exit(1);
    }
}
