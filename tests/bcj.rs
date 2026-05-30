//! Round-trip tests for the BCJ branch-converter filters.
//!
//! Every BCJ filter is a reversible transform: decode∘encode == identity.
//! These tests prove that over random bytes, real-ish instruction streams,
//! and 1-byte-granularity chunked streaming, for all eight architectures.

#![cfg(feature = "bcj")]

use compcol::bcj::{
    BcjArm, BcjArm64, BcjArmThumb, BcjIa64, BcjPpc, BcjRiscV, BcjSparc, BcjX86, Config,
};
use compcol::{Algorithm, Status};

fn lcg(seed: &mut u64) -> u8 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*seed >> 33) as u8
}
fn rand_bytes(n: usize, mut seed: u64) -> Vec<u8> {
    (0..n).map(|_| lcg(&mut seed)).collect()
}

/// Generic streaming driver over a boxed Encoder/Decoder via the trait.
fn drive<C: compcol::Encoder>(
    codec: &mut C,
    input: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let mut consumed = 0;
        while consumed < end - i {
            let (p, status) = codec.encode(&input[i + consumed..end], &mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::OutputFull => continue,
                Status::InputEmpty | Status::StreamEnd => break,
            }
        }
        i = end;
    }
    loop {
        let (p, status) = codec.finish(&mut buf).unwrap();
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

fn drive_dec<C: compcol::Decoder>(
    codec: &mut C,
    input: &[u8],
    in_chunk: usize,
    out_chunk: usize,
) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let mut consumed = 0;
        while consumed < end - i {
            let (p, status) = codec.decode(&input[i + consumed..end], &mut buf).unwrap();
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::OutputFull => continue,
                Status::InputEmpty | Status::StreamEnd => break,
            }
        }
        i = end;
    }
    loop {
        let (p, status) = codec.finish(&mut buf).unwrap();
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

macro_rules! rt_suite {
    ($name:ident, $alg:ty) => {
        mod $name {
            use super::*;

            fn encode_bulk(data: &[u8]) -> Vec<u8> {
                let mut e = <$alg>::encoder();
                drive(&mut e, data, data.len().max(1), data.len().max(1))
            }
            fn decode_bulk(data: &[u8]) -> Vec<u8> {
                let mut d = <$alg>::decoder();
                drive_dec(&mut d, data, data.len().max(1), data.len().max(1))
            }

            #[test]
            fn round_trip_random() {
                for &n in &[0usize, 1, 4, 5, 15, 16, 17, 64, 257, 1024, 4099] {
                    let data = rand_bytes(n, 0xC0DE ^ n as u64);
                    let enc = encode_bulk(&data);
                    assert_eq!(enc.len(), data.len(), "{} not 1:1", stringify!($name));
                    let dec = decode_bulk(&enc);
                    assert_eq!(dec, data, "{} round trip failed n={}", stringify!($name), n);
                }
            }

            #[test]
            fn round_trip_codeish() {
                // A stream peppered with branch-like opcodes so the
                // converter's hot path actually fires.
                let mut data = Vec::new();
                let mut seed = 0xBEEFu64;
                for k in 0..400u32 {
                    match k % 5 {
                        0 => data.extend_from_slice(&[0xE8, 0x10, 0x20, 0x30, 0x00]), // x86 call
                        1 => data.extend_from_slice(&[0x12, 0x34, 0x56, 0xEB]),       // arm bl
                        2 => data.extend_from_slice(&[0x48, 0x00, 0x12, 0x01]),       // ppc bl
                        3 => data.extend_from_slice(&[0x40, 0x00, 0x12, 0x34]),       // sparc call
                        _ => {
                            for _ in 0..16 {
                                data.push(lcg(&mut seed));
                            }
                        }
                    }
                }
                let enc = encode_bulk(&data);
                let dec = decode_bulk(&enc);
                assert_eq!(dec, data, "{} codeish round trip failed", stringify!($name));
            }

            #[test]
            fn chunked_one_byte() {
                let data = rand_bytes(2000, 0x5151 ^ 7);
                // 1-byte in / 1-byte out streaming.
                let mut e = <$alg>::encoder();
                let enc = drive(&mut e, &data, 1, 1);
                // Must match bulk encode regardless of chunking.
                assert_eq!(
                    enc,
                    encode_bulk(&data),
                    "{} chunk-dependent",
                    stringify!($name)
                );
                let mut d = <$alg>::decoder();
                let dec = drive_dec(&mut d, &enc, 1, 1);
                assert_eq!(dec, data, "{} 1-byte round trip failed", stringify!($name));
            }

            #[test]
            fn chunked_varied() {
                let data = rand_bytes(3000, 0x9999);
                for &(ic, oc) in &[
                    (3usize, 7usize),
                    (5, 5),
                    (13, 1),
                    (1, 13),
                    (16, 16),
                    (17, 3),
                ] {
                    let mut e = <$alg>::encoder();
                    let enc = drive(&mut e, &data, ic, oc);
                    assert_eq!(
                        enc,
                        encode_bulk(&data),
                        "{} chunk-dependent ic={} oc={}",
                        stringify!($name),
                        ic,
                        oc
                    );
                    let mut d = <$alg>::decoder();
                    let dec = drive_dec(&mut d, &enc, oc, ic);
                    assert_eq!(
                        dec,
                        data,
                        "{} round trip ic={} oc={}",
                        stringify!($name),
                        ic,
                        oc
                    );
                }
            }

            #[test]
            fn start_offset_round_trips() {
                let data = rand_bytes(517, 0x4242);
                let cfg = Config {
                    start_offset: 0x1000,
                };
                let mut e = <$alg>::encoder_with(cfg);
                let enc = drive(&mut e, &data, 64, 64);
                let mut d = <$alg>::decoder_with(cfg);
                let dec = drive_dec(&mut d, &enc, 64, 64);
                assert_eq!(
                    dec,
                    data,
                    "{} start-offset round trip failed",
                    stringify!($name)
                );
            }

            #[test]
            fn sub_instruction_tail() {
                // Lengths that end mid-instruction for each arch.
                for &n in &[1usize, 2, 3, 6, 18, 19] {
                    let data = rand_bytes(n, 0x7 ^ n as u64);
                    let enc = encode_bulk(&data);
                    let dec = decode_bulk(&enc);
                    assert_eq!(dec, data, "{} tail n={} failed", stringify!($name), n);
                }
            }
        }
    };
}

rt_suite!(x86, BcjX86);
rt_suite!(arm, BcjArm);
rt_suite!(armt, BcjArmThumb);
rt_suite!(arm64, BcjArm64);
rt_suite!(ppc, BcjPpc);
rt_suite!(sparc, BcjSparc);
rt_suite!(ia64, BcjIa64);
rt_suite!(riscv, BcjRiscV);

#[cfg(feature = "factory")]
#[test]
fn factory_registration_round_trips() {
    let names = [
        "bcj-x86",
        "bcj-arm",
        "bcj-armt",
        "bcj-arm64",
        "bcj-ppc",
        "bcj-sparc",
        "bcj-ia64",
        "bcj-riscv",
    ];
    let data = rand_bytes(1234, 0xF00D);
    for name in names {
        assert!(
            compcol::factory::names().contains(&name),
            "{name} not in names()"
        );
        let mut enc = compcol::factory::encoder_by_name(name).expect("encoder");
        let encoded = drive(&mut enc, &data, 100, 100);
        let mut dec = compcol::factory::decoder_by_name(name).expect("decoder");
        let decoded = drive_dec(&mut dec, &encoded, 100, 100);
        assert_eq!(decoded, data, "{name} factory round trip failed");
        assert!(compcol::factory::extension(name).is_some());
    }
}

#[test]
fn x86_is_actually_transforming() {
    // A run of identical relative calls to nearby targets should change.
    let mut data = Vec::new();
    for _ in 0..20 {
        data.extend_from_slice(&[0xE8, 0x00, 0x00, 0x00, 0x00]);
    }
    let mut e = BcjX86::encoder();
    let enc = drive(&mut e, &data, data.len(), data.len());
    assert_ne!(enc, data, "x86 filter should rewrite E8 operands");
    let mut d = BcjX86::decoder();
    assert_eq!(drive_dec(&mut d, &enc, enc.len(), enc.len()), data);
}
