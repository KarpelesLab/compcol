//! Round-trip tests for the Delta filter.

#![cfg(feature = "delta")]

use compcol::delta::{Decoder, DecoderConfig, Delta, Encoder, EncoderConfig};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

/// Drive an encoder over `input` in `in_chunk`-sized input slices and
/// `out_chunk`-sized output slices, returning the full output.
fn run_enc(enc: &mut Encoder, input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let mut consumed = 0;
        while consumed < end - i {
            let (p, status) = enc.encode(&input[i + consumed..end], &mut buf).unwrap();
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
        let (p, status) = enc.finish(&mut buf).unwrap();
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

fn run_dec(dec: &mut Decoder, input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;
    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let mut consumed = 0;
        while consumed < end - i {
            let (p, status) = dec.decode(&input[i + consumed..end], &mut buf).unwrap();
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

fn lcg(seed: &mut u64) -> u8 {
    *seed = seed
        .wrapping_mul(6364136223846793005)
        .wrapping_add(1442695040888963407);
    (*seed >> 33) as u8
}

fn rand_bytes(n: usize, mut seed: u64) -> Vec<u8> {
    (0..n).map(|_| lcg(&mut seed)).collect()
}

fn round_trip(data: &[u8], dist: usize) {
    let mut enc = Delta::encoder_with(EncoderConfig { dist });
    let encoded = run_enc(&mut enc, data, data.len().max(1), data.len().max(1));
    assert_eq!(encoded.len(), data.len(), "delta is 1:1 in length");
    let mut dec = Delta::decoder_with(DecoderConfig { dist });
    let decoded = run_dec(
        &mut dec,
        &encoded,
        encoded.len().max(1),
        encoded.len().max(1),
    );
    assert_eq!(decoded, data, "round trip mismatch at dist={dist}");
}

#[test]
fn round_trip_random_many_distances() {
    for &dist in &[1usize, 2, 3, 4, 5, 8, 16, 100, 255, 256] {
        for &n in &[0usize, 1, 2, 7, 256, 257, 1000] {
            let data = rand_bytes(n, 0x1234_5678 ^ (dist as u64) ^ (n as u64));
            round_trip(&data, dist);
        }
    }
}

#[test]
fn round_trip_patterned() {
    // Linear ramp — delta-1 should turn it into a constant.
    let ramp: Vec<u8> = (0..1000u32).map(|x| x as u8).collect();
    round_trip(&ramp, 1);

    let mut enc = Delta::encoder_with(EncoderConfig { dist: 1 });
    let encoded = run_enc(&mut enc, &ramp, 1000, 1000);
    // After the first byte, every delta of a +1 ramp is 1.
    assert!(encoded[1..].iter().all(|&b| b == 1));
}

#[test]
fn chunked_one_byte_granularity() {
    for &dist in &[1usize, 3, 4, 256] {
        let data = rand_bytes(523, 0xABCD ^ dist as u64);
        let mut enc = Delta::encoder_with(EncoderConfig { dist });
        let encoded = run_enc(&mut enc, &data, 1, 1);
        let mut dec = Delta::decoder_with(DecoderConfig { dist });
        let decoded = run_dec(&mut dec, &encoded, 1, 1);
        assert_eq!(decoded, data, "1-byte chunk round trip failed dist={dist}");

        // Reference: bulk encode must equal chunked encode.
        let mut enc2 = Delta::encoder_with(EncoderConfig { dist });
        let bulk = run_enc(&mut enc2, &data, data.len(), data.len());
        assert_eq!(bulk, encoded, "chunking changed delta output dist={dist}");
    }
}

#[test]
fn empty_input() {
    round_trip(&[], 1);
    round_trip(&[], 256);
}

#[test]
fn reset_reuses_config() {
    let mut enc = Delta::encoder_with(EncoderConfig { dist: 4 });
    let a = rand_bytes(100, 1);
    let b = rand_bytes(100, 2);
    let ea = run_enc(&mut enc, &a, 100, 100);
    enc.reset();
    let eb = run_enc(&mut enc, &b, 100, 100);

    let mut enc_fresh = Delta::encoder_with(EncoderConfig { dist: 4 });
    let eb_fresh = run_enc(&mut enc_fresh, &b, 100, 100);
    assert_eq!(eb, eb_fresh, "reset must restore fresh state");
    let _ = ea;
}

#[test]
fn invalid_distance_rejected() {
    let mut enc0 = Delta::encoder_with(EncoderConfig { dist: 0 });
    let mut buf = [0u8; 16];
    assert!(matches!(
        enc0.encode(&[1, 2, 3], &mut buf),
        Err(Error::Unsupported)
    ));

    let mut enc_big = Delta::encoder_with(EncoderConfig { dist: 257 });
    assert!(matches!(
        enc_big.encode(&[1, 2, 3], &mut buf),
        Err(Error::Unsupported)
    ));

    let mut dec0 = Delta::decoder_with(DecoderConfig { dist: 0 });
    assert!(matches!(
        dec0.decode(&[1, 2, 3], &mut buf),
        Err(Error::Unsupported)
    ));
}

#[test]
fn default_distance_is_one() {
    assert_eq!(EncoderConfig::default().dist, 1);
    assert_eq!(DecoderConfig::default().dist, 1);
}

#[cfg(feature = "factory")]
#[test]
fn factory_registration_round_trips() {
    assert!(compcol::factory::names().contains(&"delta"));
    assert_eq!(compcol::factory::extension("delta"), Some("delta"));
    let data = rand_bytes(777, 0xCAFE);
    // Factory uses the default config (dist = 1).
    let mut enc = compcol::factory::encoder_by_name("delta").expect("encoder");
    let mut buf = vec![0u8; 256];
    let mut encoded = Vec::new();
    let mut consumed = 0;
    while consumed < data.len() {
        let (p, s) = enc.encode(&data[consumed..], &mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(s, Status::InputEmpty) {
            break;
        }
    }
    loop {
        let (p, s) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        if matches!(s, Status::StreamEnd) {
            break;
        }
    }
    let mut dec = compcol::factory::decoder_by_name("delta").expect("decoder");
    let mut decoded = Vec::new();
    let mut consumed = 0;
    while consumed < encoded.len() {
        let (p, s) = dec.decode(&encoded[consumed..], &mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(s, Status::InputEmpty | Status::StreamEnd) {
            break;
        }
    }
    assert_eq!(decoded, data, "delta factory round trip failed");
}
