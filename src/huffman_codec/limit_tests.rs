//! Output-limit tests: the declared length in the header is enough to refuse
//! a stream, before it is buffered or decoded.

use super::*;
use crate::limit::LimitedDecoder;
use crate::traits::{Decoder as _, Status};
use crate::vec::decompress_to_vec_capped;
use alloc::vec;
use alloc::vec::Vec;

const BOMB_LEN: usize = 256 * 1024;
const CAP: u64 = 4096;

/// A valid two-symbol stream decoding to `BOMB_LEN` bytes. Its length
/// varint is 3 bytes long.
fn bomb() -> Vec<u8> {
    let plain: Vec<u8> = (0..BOMB_LEN)
        .map(|i| if i % 7 == 0 { b'b' } else { b'a' })
        .collect();
    encode_stream(&plain)
}

/// Feed everything in one `decode` call, then `finish` to the end.
fn drain<D: crate::traits::Decoder>(dec: &mut D, stream: &[u8]) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; 1024];
    let mut out = Vec::new();
    let mut consumed = 0;
    while consumed < stream.len() {
        let (p, status) = dec.decode(&stream[consumed..], &mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        consumed += p.consumed;
        if matches!(status, Status::StreamEnd) {
            return Ok(out);
        }
    }
    loop {
        let (p, status) = dec.finish(&mut buf)?;
        out.extend_from_slice(&buf[..p.written]);
        if matches!(status, Status::StreamEnd) {
            return Ok(out);
        }
    }
}

#[test]
fn first_decode_call_refuses_an_oversized_stream() {
    let bomb = bomb();
    let mut dec = LimitedDecoder::new(Decoder::new(), CAP);
    let mut buf = [0u8; 64];
    assert_eq!(
        dec.decode(&bomb, &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
    // Nothing of the refused stream was kept, nothing was decoded.
    assert_eq!(dec.get_ref().input.capacity(), 0);
    assert_eq!(dec.get_ref().output.capacity(), 0);
    // The refusal sticks until `reset`.
    assert_eq!(
        dec.decode(&bomb[..1], &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
    assert_eq!(
        dec.finish(&mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
    assert_eq!(dec.get_ref().output.capacity(), 0);
}

#[test]
fn refused_as_soon_as_the_varint_is_complete() {
    let bomb = bomb();
    let mut dec = LimitedDecoder::new(Decoder::new(), CAP);
    let mut buf = [0u8; 64];
    let mut fed = 0;
    let err = loop {
        match dec.decode(&bomb[fed..fed + 1], &mut buf) {
            Ok((p, _)) => {
                assert_eq!(p.consumed, 1);
                fed += 1;
            }
            Err(e) => break e,
        }
    };
    assert_eq!(err, Error::OutputLimitExceeded);
    // 256 KiB is a 3-byte varint: two bytes accepted, the third refused.
    assert_eq!(fed, 2);
    assert_eq!(dec.get_ref().input.len(), 2);
}

#[test]
fn exact_limit_succeeds_one_less_fails() {
    let payload: Vec<u8> = (0..10_000u32).map(|i| (i % 23) as u8).collect();
    let stream = encode_stream(&payload);
    let len = payload.len() as u64;

    assert_eq!(
        decompress_to_vec_capped::<Huffman>(&stream, len).unwrap(),
        payload
    );
    assert_eq!(
        decompress_to_vec_capped::<Huffman>(&stream, u64::MAX).unwrap(),
        payload
    );
    assert_eq!(
        decompress_to_vec_capped::<Huffman>(&stream, len - 1).unwrap_err(),
        Error::OutputLimitExceeded
    );
    assert_eq!(
        decompress_to_vec_capped::<Huffman>(&bomb(), CAP).unwrap_err(),
        Error::OutputLimitExceeded
    );

    let mut dec = LimitedDecoder::new(Decoder::new(), len);
    assert_eq!(drain(&mut dec, &stream).unwrap(), payload);

    // The empty stream fits any limit, zero included.
    assert_eq!(
        decompress_to_vec_capped::<Huffman>(&encode_stream(&[]), 0).unwrap(),
        b""
    );
}

#[test]
fn single_symbol_stream_is_refused_too() {
    // The degenerate one-symbol path builds its output with one `resize`.
    let stream = encode_stream(&vec![b'z'; BOMB_LEN]);
    assert_eq!(
        decode_stream(&stream, CAP).unwrap_err(),
        Error::OutputLimitExceeded
    );
    assert_eq!(
        decode_stream(&stream, BOMB_LEN as u64).unwrap().len(),
        BOMB_LEN
    );
}

#[test]
fn limit_survives_reset() {
    let bomb = bomb();
    let small = encode_stream(b"hello");
    let mut dec = LimitedDecoder::new(Decoder::new(), CAP);
    let mut buf = [0u8; 64];

    assert_eq!(
        dec.decode(&bomb, &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
    dec.reset();
    // The error state is gone, the limit is not.
    assert_eq!(drain(&mut dec, &small).unwrap(), b"hello");
    dec.reset();
    assert_eq!(
        dec.decode(&bomb, &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
}

#[test]
fn limit_set_after_buffering_is_enforced_by_finish() {
    let bomb = bomb();
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    dec.decode(&bomb, &mut buf).unwrap();
    dec.set_output_limit(CAP);
    assert_eq!(
        dec.finish(&mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
    assert_eq!(dec.output.capacity(), 0);
}

#[test]
fn malformed_varint_is_still_reported_as_corrupt() {
    // Eleven continuation bytes: not a u64 varint. The limit must not turn
    // that into a different error (or hide it).
    let stream = [0xFFu8; 16];
    let mut dec = LimitedDecoder::new(Decoder::new(), CAP);
    assert_eq!(drain(&mut dec, &stream).unwrap_err(), Error::Corrupt);
    // Fed a byte at a time as well.
    let mut dec = LimitedDecoder::new(Decoder::new(), CAP);
    let mut buf = [0u8; 8];
    for b in stream.chunks(1) {
        dec.decode(b, &mut buf).unwrap();
    }
    assert_eq!(dec.finish(&mut buf).unwrap_err(), Error::Corrupt);
}

#[cfg(feature = "factory")]
#[test]
fn boxed_factory_decoder_refuses_from_first_decode() {
    let bomb = bomb();
    let boxed = crate::factory::decoder_by_name("huffman").unwrap();
    let mut dec = LimitedDecoder::new(boxed, CAP);
    let mut buf = [0u8; 64];
    assert_eq!(
        dec.decode(&bomb, &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );

    // And a stream within the limit still decodes through the box.
    let boxed = crate::factory::decoder_by_name("huffman").unwrap();
    let mut dec = LimitedDecoder::new(boxed, CAP);
    assert_eq!(drain(&mut dec, &encode_stream(b"hello")).unwrap(), b"hello");
}
