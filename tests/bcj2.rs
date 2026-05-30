//! Round-trip tests for the public BCJ2 4-stream filter API.
//!
//! `compcol::bcj2::decode(main, call, jump, rc, out_len)` recombines the four
//! streams produced by `compcol::bcj2::encode(input)` back into `input`.

#![cfg(feature = "bcj2")]

use compcol::bcj2;

fn lcg(seed: &mut u64) -> u8 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*seed >> 33) as u8
}

fn rand_bytes(n: usize, mut seed: u64) -> Vec<u8> {
    (0..n).map(|_| lcg(&mut seed)).collect()
}

fn roundtrip(input: &[u8]) {
    let (main, call, jump, rc) = bcj2::encode(input);
    let got = bcj2::decode(&main, &call, &jump, &rc, input.len()).expect("decode ok");
    assert_eq!(got, input, "BCJ2 round-trip mismatch (len={})", input.len());
}

#[test]
fn random_payloads() {
    for (n, seed) in [
        (0usize, 1u64),
        (1, 2),
        (7, 3),
        (256, 4),
        (4096, 5),
        (65537, 6),
    ] {
        roundtrip(&rand_bytes(n, seed));
    }
}

#[test]
fn synthetic_x86_with_branches() {
    // A stream peppered with E8/E9/0F8x branches and varied operands.
    let mut v = Vec::new();
    let mut s = 99u64;
    for k in 0..400u32 {
        // some filler
        for _ in 0..(lcg(&mut s) % 5) {
            v.push(lcg(&mut s));
        }
        match k % 3 {
            0 => {
                v.push(0xE8);
                v.extend_from_slice(&k.wrapping_mul(13).to_le_bytes());
            }
            1 => {
                v.push(0xE9);
                v.extend_from_slice(&(0xDEAD_0000u32 ^ k).to_le_bytes());
            }
            _ => {
                v.push(0x0F);
                v.push(0x80 | (lcg(&mut s) & 0x0F));
                v.extend_from_slice(&k.to_le_bytes());
            }
        }
    }
    v.extend_from_slice(&[0u8; 8]);
    roundtrip(&v);
}

#[test]
fn errors_on_truncation() {
    let (main, call, jump, rc) = bcj2::encode(b"hello world payload");
    // Asking for more output than the streams can supply must error, not panic.
    assert!(bcj2::decode(&main, &call, &jump, &rc, 10_000).is_err());
    // A too-short rc stream must error.
    assert!(bcj2::decode(&main, &call, &jump, &[0u8; 2], 5).is_err());
}
