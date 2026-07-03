//! Focused micro-benchmark for a single codec + input, no subprocess.
//!
//! Usage: micro <algo> <input:lorem|zeros|random|source> <size_bytes> <iters> <mode:enc|dec|both>
//!
//! Prints min and median ns/byte and MB/s over `iters` timed runs (after 3
//! warmups). Min wall-clock is the stable metric for single-threaded CPU work.

use std::time::Instant;

use compcol::factory;
use compcol::Status;

const LOREM: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. Ut enim \
ad minim veniam, quis nostrud exercitation ullamco laboris nisi ut aliquip \
ex ea commodo consequat. Duis aute irure dolor in reprehenderit in voluptate \
velit esse cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat \
cupidatat non proident, sunt in culpa qui officia deserunt mollit anim id \
est laborum. ";

fn build_input(kind: &str, size: usize) -> Vec<u8> {
    match kind {
        "lorem" => {
            let mut d = Vec::with_capacity(size);
            while d.len() < size {
                let t = LOREM.len().min(size - d.len());
                d.extend_from_slice(&LOREM[..t]);
            }
            d
        }
        "zeros" => vec![0u8; size],
        "random" => {
            let mut d = Vec::with_capacity(size);
            let mut s: u32 = 0xDEAD_BEEF;
            while d.len() < size {
                s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                d.push((s >> 16) as u8);
            }
            d
        }
        // Semi-realistic: mix of repeated text with random-ish perturbations.
        "source" => {
            let mut d = Vec::with_capacity(size);
            let mut s: u32 = 0x1234_5678;
            let words: &[&[u8]] = &[
                b"fn ", b"let ", b"mut ", b"self.", b"return ", b"match ", b"=> ",
                b"Ok(", b"Err(", b"Vec<u8>", b"usize", b"->", b" {\n", b"}\n",
                b"    ", b"if ", b"else ", b"for ", b"while ", b".iter()", b"()",
            ];
            while d.len() < size {
                s = s.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                let w = words[(s >> 20) as usize % words.len()];
                d.extend_from_slice(w);
            }
            d.truncate(size);
            d
        }
        _ => panic!("unknown input kind {kind}"),
    }
}

fn encode(algo: &str, input: &[u8]) -> Vec<u8> {
    let mut enc = factory::encoder_by_name(algo).expect("unknown algo");
    let mut out = Vec::with_capacity(input.len() + 4096);
    let mut buf = vec![0u8; 256 * 1024];
    let mut consumed = 0;
    while consumed < input.len() {
        let (p, status) = enc.encode(&input[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::InputEmpty | Status::StreamEnd => break,
            Status::OutputFull => continue,
        }
    }
    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            _ => {
                if p.written == 0 {
                    break;
                }
            }
        }
    }
    out
}

fn decode(algo: &str, enc: &[u8]) -> Vec<u8> {
    let mut dec = factory::decoder_by_name(algo).expect("unknown algo");
    let mut out = Vec::with_capacity(enc.len() * 4);
    let mut buf = vec![0u8; 256 * 1024];
    let mut consumed = 0;
    while consumed < enc.len() {
        let (p, status) = dec.decode(&enc[consumed..], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        match status {
            Status::InputEmpty | Status::StreamEnd => break,
            Status::OutputFull => continue,
        }
    }
    loop {
        let (p, _s) = dec.decode(&[], &mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        if p.written == 0 {
            break;
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        out.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            _ => {
                if p.written == 0 {
                    break;
                }
            }
        }
    }
    out
}

fn time_it(iters: usize, bytes: usize, mut f: impl FnMut()) -> (f64, f64) {
    for _ in 0..3 {
        f();
    }
    let mut samples: Vec<f64> = Vec::with_capacity(iters);
    for _ in 0..iters {
        let t = Instant::now();
        f();
        samples.push(t.elapsed().as_secs_f64());
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    let min = samples[0];
    let med = samples[samples.len() / 2];
    let mbps = |s: f64| bytes as f64 / s / 1e6;
    // return (min MB/s, median MB/s)
    (mbps(min), mbps(med))
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 6 {
        eprintln!("usage: micro <algo> <lorem|zeros|random|source> <size> <iters> <enc|dec|both>");
        std::process::exit(2);
    }
    let algo = &args[1];
    let kind = &args[2];
    let size: usize = args[3].parse().unwrap();
    let iters: usize = args[4].parse().unwrap();
    let mode = &args[5];

    let input = build_input(kind, size);
    let encoded = encode(algo, &input);
    // correctness check
    let round = decode(algo, &encoded);
    let ok = round == input;

    println!(
        "# {algo} {kind} {size}B  out={} ratio={:.4} roundtrip={}",
        encoded.len(),
        encoded.len() as f64 / input.len() as f64,
        if ok { "OK" } else { "MISMATCH" }
    );
    if !ok {
        eprintln!("ROUND TRIP MISMATCH for {algo}");
    }

    if mode == "enc" || mode == "both" {
        let (mn, md) = time_it(iters, input.len(), || {
            let _ = encode(algo, &input);
        });
        println!("enc  min={mn:.1} MB/s  median={md:.1} MB/s");
    }
    if mode == "dec" || mode == "both" {
        let (mn, md) = time_it(iters, input.len(), || {
            let _ = decode(algo, &encoded);
        });
        println!("dec  min={mn:.1} MB/s  median={md:.1} MB/s");
    }
}
