#![cfg(feature = "qpack")]
//! Integration tests for the QPACK module's public API.

use compcol::hpack::HeaderField;
use compcol::qpack::{QpackDecoder, QpackEncoder};

/// Regression: the HPACK/QPACK Huffman decode table used to be rebuilt for
/// every Huffman-coded string, so an encoder stream of thousands of tiny
/// inserts with empty Huffman strings cost seconds of CPU for a few KiB of
/// input. The table is now a compile-time `static`. The old code needed many
/// seconds here; the fixed code needs a few milliseconds, so the bound below
/// is extremely generous.
#[test]
fn many_empty_huffman_inserts_are_cheap() {
    // Set Dynamic Table Capacity = 4096, then 3000 × "Insert with Literal
    // Name": Huffman-flagged name of length 0, Huffman-flagged value of
    // length 0. Each entry costs 32 bytes, so old ones are evicted as new
    // ones arrive.
    let mut stream = vec![0x3f, 0xe1, 0x1f];
    for _ in 0..3000 {
        stream.extend_from_slice(&[0x60, 0x80]);
    }
    let mut dec = QpackDecoder::with_limits(4096, 65536);
    let start = std::time::Instant::now();
    dec.feed_encoder_stream(&stream).unwrap();
    let elapsed = start.elapsed();
    assert!(
        elapsed < std::time::Duration::from_secs(2),
        "6000 empty Huffman strings took {elapsed:?}"
    );
}

/// The encoder stream is a QUIC byte stream: chunks end wherever the
/// transport cut them. `feed_encoder_stream` used to apply the complete
/// instructions of a chunk and then fail with `UnexpectedEnd` on a partial
/// trailing one, without saying how much it had consumed — a caller that
/// buffered and retried re-applied the earlier inserts and silently
/// desynchronised the dynamic table. The decoder now keeps the partial
/// instruction itself.
#[test]
fn encoder_stream_can_be_fed_in_arbitrary_pieces() {
    // Set Dynamic Table Capacity = 4096; Insert with Literal Name `ab: cd`;
    // Insert with Literal Name `ef: gh`.
    let full = [
        0x3f, 0xe1, 0x1f, 0x42, b'a', b'b', 0x02, b'c', b'd', 0x42, b'e', b'f', 0x02, b'g', b'h',
    ];
    let mut dec = QpackDecoder::with_limits(4096, 65536);
    assert_eq!(dec.feed_encoder_stream(&full[..12]), Ok(()));
    assert_eq!(dec.insert_count(), 1);
    assert_eq!(dec.encoder_stream_pending(), 3);
    assert_eq!(dec.feed_encoder_stream(&full[12..]), Ok(()));
    assert_eq!(dec.insert_count(), 2);
    assert_eq!(dec.encoder_stream_pending(), 0);
}

/// Sections encoded against the dynamic table decode identically whether
/// the encoder stream reaches the decoder whole or cut at any point.
#[test]
fn field_sections_decode_after_split_encoder_stream() {
    let sections: Vec<Vec<HeaderField>> = (0..5u8)
        .map(|i| {
            vec![
                HeaderField::new(b":method", b"GET"),
                HeaderField::new(b":authority", &[b'a' + i; 11]),
                HeaderField::new(b"x-request-id", &[b'0' + i; 24]),
                HeaderField::new(b"x-constant", b"same every time"),
            ]
        })
        .collect();
    let mut enc = QpackEncoder::with_dynamic_table(512);
    let encoded: Vec<_> = sections.iter().map(|s| enc.encode(s)).collect();
    let stream: Vec<u8> = encoded
        .iter()
        .flat_map(|e| e.encoder_stream.iter().copied())
        .collect();
    assert!(stream.len() > 100);
    // Only the last section is decoded: earlier ones may reference entries
    // that later inserts evicted.
    let (last, want) = (encoded.last().unwrap(), sections.last().unwrap());

    for cut in 0..=stream.len() {
        let mut dec = QpackDecoder::with_limits(512, 65536);
        dec.feed_encoder_stream(&stream[..cut]).unwrap();
        dec.feed_encoder_stream(&stream[cut..]).unwrap();
        assert_eq!(dec.encoder_stream_pending(), 0, "cut {cut}");
        assert_eq!(
            &dec.decode_field_section(&last.field_section).unwrap(),
            want,
            "cut {cut}"
        );
    }
    let mut dec = QpackDecoder::with_limits(512, 65536);
    for b in &stream {
        dec.feed_encoder_stream(std::slice::from_ref(b)).unwrap();
    }
    assert_eq!(
        &dec.decode_field_section(&last.field_section).unwrap(),
        want
    );
}

/// Feeding a long instruction one byte at a time must not re-decode what
/// has already arrived on every call: a partial instruction is only
/// measured (its integers), never decoded, until it is complete.
#[test]
fn byte_at_a_time_feeding_is_linear() {
    let cap = 1 << 20;
    let mut dec = QpackDecoder::with_limits(cap, 65536);
    // Set Dynamic Table Capacity = 1 MiB.
    let mut stream = vec![0x3f, 0xe1, 0xff, 0x3f];
    // Insert with Literal Name: a Huffman name of 300 000 × 'a' (5 bits
    // each: 187 500 octets), then a raw value of 100 000 octets.
    let name = compcol::hpack::huffman::encode(&[b'a'; 300_000]);
    assert_eq!(name.len(), 187_500);
    stream.extend_from_slice(&[0x7f, 0xcd, 0xb8, 0x0b]);
    stream.extend_from_slice(&name);
    stream.extend_from_slice(&[0x7f, 0xa1, 0x8c, 0x06]);
    stream.resize(stream.len() + 100_000, b'v');
    let start = std::time::Instant::now();
    for b in &stream {
        dec.feed_encoder_stream(std::slice::from_ref(b)).unwrap();
    }
    let elapsed = start.elapsed();
    assert_eq!(dec.encoder_stream_pending(), 0);
    assert_eq!(dec.insert_count(), 1);
    // Re-decoding the name for each of the 100 000 value bytes would take
    // minutes.
    assert!(
        elapsed < std::time::Duration::from_secs(10),
        "one-byte feeding took {elapsed:?}"
    );
}
