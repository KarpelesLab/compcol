//! Output-limit tests: the block headers are enough to refuse a stream,
//! before the block that crosses the limit is buffered or inverted.

extern crate alloc;
use alloc::vec;
use alloc::vec::Vec;

use super::{Bwt, Decoder, EncoderConfig};
use crate::error::Error;
use crate::limit::LimitedDecoder;
use crate::traits::{Decoder as _, RawDecoder, Status};
use crate::vec::{compress_to_vec_with, decompress_to_vec_capped};

const BLOCK: usize = 16 * 1024;
/// Encoded size of one full block: 8-byte header + the last column.
const ENC_BLOCK: usize = 8 + BLOCK;

fn plain(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i % 251) as u8 ^ (i >> 9) as u8).collect()
}

/// `blocks` full blocks of `BLOCK` bytes each.
fn stream(blocks: usize) -> Vec<u8> {
    let enc = compress_to_vec_with::<Bwt>(
        &plain(blocks * BLOCK),
        EncoderConfig::default().with_block_size(BLOCK),
    )
    .unwrap();
    assert_eq!(enc.len(), blocks * ENC_BLOCK);
    enc
}

/// Feed `encoded` in `chunk`-byte `decode` calls, then `finish` to the end.
fn drain<D: crate::traits::Decoder>(
    dec: &mut D,
    encoded: &[u8],
    chunk: usize,
) -> Result<Vec<u8>, Error> {
    let mut buf = vec![0u8; 1024];
    let mut out = Vec::new();
    for piece in encoded.chunks(chunk) {
        let mut consumed = 0;
        while consumed < piece.len() {
            let (p, status) = dec.decode(&piece[consumed..], &mut buf)?;
            out.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            if matches!(status, Status::StreamEnd) {
                return Ok(out);
            }
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

/// Feed one byte per `decode` call; return how many were accepted before
/// the first error, and that error.
fn feed_bytewise(dec: &mut LimitedDecoder<Decoder>, encoded: &[u8]) -> (usize, Error) {
    let mut buf = [0u8; 16];
    let mut fed = 0;
    loop {
        match dec.decode(&encoded[fed..fed + 1], &mut buf) {
            Ok((p, _)) => {
                assert_eq!(p.consumed, 1);
                fed += 1;
            }
            Err(e) => return (fed, e),
        }
    }
}

#[test]
fn first_decode_call_refuses_an_oversized_stream() {
    let enc = stream(4);
    // Two blocks fit, the third crosses.
    let mut dec = LimitedDecoder::new(Decoder::new(), 40_000);
    let mut buf = [0u8; 64];
    assert_eq!(
        dec.decode(&enc, &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
    // The whole stream was offered in one call and none of it was kept;
    // nothing was inverted.
    assert_eq!(dec.get_ref().input.capacity(), 0);
    assert_eq!(dec.get_ref().output.capacity(), 0);
    // The refusal sticks until `reset`.
    assert_eq!(
        dec.decode(&enc[..1], &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
    assert_eq!(
        dec.finish(&mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
    assert_eq!(dec.get_ref().output.capacity(), 0);
}

#[test]
fn single_block_refused_from_its_length_field() {
    let enc = stream(1);
    let mut dec = LimitedDecoder::new(Decoder::new(), 4096);
    let (fed, err) = feed_bytewise(&mut dec, &enc);
    assert_eq!(err, Error::OutputLimitExceeded);
    // Three bytes of the u32 length accepted, the fourth refused.
    assert_eq!(fed, 3);
}

#[test]
fn refused_at_the_header_of_the_block_that_crosses() {
    let enc = stream(4);
    let mut dec = LimitedDecoder::new(Decoder::new(), 40_000);
    let (fed, err) = feed_bytewise(&mut dec, &enc);
    assert_eq!(err, Error::OutputLimitExceeded);
    // Blocks 1 and 2 in full, then the third block's length field.
    assert_eq!(fed, 2 * ENC_BLOCK + 3);
    assert_eq!(dec.get_ref().input.len(), fed);
    assert_eq!(dec.get_ref().output.capacity(), 0);
}

#[test]
fn refusal_point_does_not_depend_on_chunking() {
    let enc = stream(4);
    for chunk in [1usize, 3, 7, 4096, ENC_BLOCK - 1, ENC_BLOCK, ENC_BLOCK + 5] {
        let mut dec = LimitedDecoder::new(Decoder::new(), 40_000);
        assert_eq!(
            drain(&mut dec, &enc, chunk).unwrap_err(),
            Error::OutputLimitExceeded,
            "chunk={chunk}"
        );
        // Never more buffered than what precedes the refused chunk.
        assert!(
            dec.get_ref().input.len() < 2 * ENC_BLOCK + 4,
            "chunk={chunk}"
        );
        assert_eq!(dec.get_ref().output.capacity(), 0, "chunk={chunk}");

        // Within the limit the same chunking decodes normally.
        let mut dec = LimitedDecoder::new(Decoder::new(), 4 * BLOCK as u64);
        assert_eq!(
            drain(&mut dec, &enc, chunk).unwrap(),
            plain(4 * BLOCK),
            "chunk={chunk}"
        );
    }
}

#[test]
fn exact_limit_succeeds_one_less_fails() {
    let enc = stream(4);
    let len = 4 * BLOCK as u64;
    assert_eq!(
        decompress_to_vec_capped::<Bwt>(&enc, len).unwrap(),
        plain(4 * BLOCK)
    );
    assert_eq!(
        decompress_to_vec_capped::<Bwt>(&enc, u64::MAX).unwrap(),
        plain(4 * BLOCK)
    );
    assert_eq!(
        decompress_to_vec_capped::<Bwt>(&enc, len - 1).unwrap_err(),
        Error::OutputLimitExceeded
    );
    // The empty stream (zero blocks) fits any limit, zero included.
    assert_eq!(decompress_to_vec_capped::<Bwt>(&[], 0).unwrap(), b"");
}

#[test]
fn limit_survives_reset() {
    let enc = stream(4);
    let small = compress_to_vec_with::<Bwt>(b"hello", EncoderConfig::default()).unwrap();
    let mut dec = LimitedDecoder::new(Decoder::new(), 40_000);
    let mut buf = [0u8; 64];

    assert_eq!(
        dec.decode(&enc, &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
    dec.reset();
    // The error state is gone, the limit is not.
    assert_eq!(drain(&mut dec, &small, 4096).unwrap(), b"hello");
    dec.reset();
    assert_eq!(
        dec.decode(&enc, &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );
}

#[test]
fn limit_set_after_buffering_is_enforced_by_finish() {
    let enc = stream(4);
    let mut dec = Decoder::new();
    let mut buf = [0u8; 64];
    dec.decode(&enc, &mut buf).unwrap();
    dec.raw_set_output_limit(40_000);
    for _ in 0..3 {
        assert_eq!(
            dec.finish(&mut buf).unwrap_err(),
            Error::OutputLimitExceeded
        );
        // The two blocks that fit were inverted; the third never was, and
        // repeated calls do not build more.
        assert_eq!(dec.output.len(), 2 * BLOCK);
    }
}

#[test]
fn corrupt_header_is_still_reported_as_corrupt() {
    // A good block followed by a zero-length one: the limit must not turn
    // that into a different error (or hide it).
    let mut enc = stream(1);
    enc.extend_from_slice(&[0u8; 8]);
    enc.extend_from_slice(&stream(3));
    for chunk in [1usize, 4096, usize::MAX] {
        let mut dec = LimitedDecoder::new(Decoder::new(), 20_000);
        assert_eq!(
            drain(&mut dec, &enc, chunk).unwrap_err(),
            Error::Corrupt,
            "chunk={chunk}"
        );
    }
}

#[cfg(feature = "factory")]
#[test]
fn boxed_factory_decoder_refuses_from_first_decode() {
    let enc = stream(4);
    let boxed = crate::factory::decoder_by_name("bwt").unwrap();
    let mut dec = LimitedDecoder::new(boxed, 40_000);
    let mut buf = [0u8; 64];
    assert_eq!(
        dec.decode(&enc, &mut buf).unwrap_err(),
        Error::OutputLimitExceeded
    );

    // And a stream within the limit still decodes through the box.
    let boxed = crate::factory::decoder_by_name("bwt").unwrap();
    let mut dec = LimitedDecoder::new(boxed, 4 * BLOCK as u64);
    assert_eq!(drain(&mut dec, &enc, 5000).unwrap(), plain(4 * BLOCK));
}
