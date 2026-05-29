//! Tests for the public raw-block API exposed at `compcol::lz4::block`
//! and `compcol::lzo::block` (issue #9). Use case: SquashFS-style
//! containers that embed a single LZ4-block or LZO1X-block payload
//! with no framing.

#![cfg(any(feature = "lz4", feature = "lzo"))]

#[cfg(feature = "lz4")]
mod lz4_raw {
    use compcol::lz4::block::{compress_bound, decode_block, encode_block};

    #[test]
    fn round_trip_hello_world() {
        let input = b"hello world hello world hello world\n";
        let mut out = Vec::new();
        encode_block(input, &mut out);
        assert!(!out.is_empty());

        let mut decoded = Vec::new();
        decode_block(&out, &mut decoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trip_4kib_repeating() {
        let input: Vec<u8> = (0..4096).map(|i| (i % 17) as u8).collect();
        let mut out = Vec::new();
        encode_block(&input, &mut out);
        assert!(out.len() < input.len(), "should compress");

        let mut decoded = Vec::new();
        decode_block(&out, &mut decoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn compress_bound_is_sufficient_headroom() {
        let input = b"some data";
        assert!(compress_bound(input.len()) >= input.len());
        let mut out = Vec::with_capacity(compress_bound(input.len()));
        encode_block(input, &mut out);
        assert!(out.len() <= compress_bound(input.len()));
    }
}

#[cfg(feature = "lzo")]
mod lzo_raw {
    use compcol::lzo::block::{compress_bound, decode_block, encode_block};

    #[test]
    fn round_trip_hello_world() {
        let input = b"hello world hello world hello world\n";
        let mut out = Vec::new();
        encode_block(input, &mut out);
        assert!(!out.is_empty());

        let mut decoded = Vec::new();
        decode_block(&out, &mut decoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn round_trip_4kib_repeating() {
        let input: Vec<u8> = (0..4096).map(|i| (i % 17) as u8).collect();
        let mut out = Vec::new();
        encode_block(&input, &mut out);
        assert!(out.len() < input.len(), "should compress");

        let mut decoded = Vec::new();
        decode_block(&out, &mut decoded).unwrap();
        assert_eq!(decoded, input);
    }

    #[test]
    fn compress_bound_is_sufficient_headroom() {
        let input = b"some data";
        assert!(compress_bound(input.len()) >= input.len());
    }
}
