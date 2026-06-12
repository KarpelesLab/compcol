#![no_main]
use compcol::hpack::{huffman, HpackDecoder};
use libfuzzer_sys::fuzz_target;

// Smoke property: neither the HPACK header decoder nor the standalone
// "h2 huffman" string decoder may panic on arbitrary attacker-controlled
// input. libfuzzer feeds us garbage; any panic/abort trips the harness.
//
// Both are pure whole-buffer transforms (the HPACK header block decoder is
// the primary attack surface — it walks the integer/string/index
// representations), so we just call them and discard the result.
fuzz_target!(|data: &[u8]| {
    // HPACK header block: bounded table so a hostile size update can't grow
    // state without limit.
    let mut dec = HpackDecoder::with_max_table_size(4096);
    let _ = dec.decode(data);

    // The §5.2 Huffman string primitive on its own.
    let _ = huffman::decode(data);
});
