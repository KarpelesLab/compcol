#![cfg(feature = "qpack")]
//! Integration tests for the QPACK module's public API.

use compcol::qpack::QpackDecoder;

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
