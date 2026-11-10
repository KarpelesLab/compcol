#![no_main]
//! HPACK / QPACK header decoders: dynamic-table logic and the decoded-size
//! caps. Neither is a `Decoder`, so no other target reaches them.
//!
//!   byte 0, 1  split point (little endian, clamped to the payload length)
//!   byte 2     limits: low nibble picks the table size, high nibble the
//!              header-list / field-section size cap
//!   rest       payload, cut at the split point into parts A and B
//!
//! HPACK:  one decoder decodes A and then B as two header blocks, so B runs
//!         against whatever dynamic table A left behind.
//! QPACK:  A is the encoder stream (table inserts), B the field section.
//!
//! Must not panic, and a successfully decoded list must fit the configured
//! cap, counted as the RFCs do (name + value + 32 per field).

use compcol::hpack::{HeaderField, HpackDecoder};
use compcol::qpack::QpackDecoder;
use libfuzzer_sys::fuzz_target;

const TABLE_SIZES: [usize; 8] = [0, 1, 32, 64, 256, 4096, 16384, 65536];
const LIST_LIMITS: [usize; 8] = [0, 1, 33, 100, 1024, 4096, 65536, usize::MAX];

fn check(what: &str, fields: &[HeaderField], limit: usize) {
    let size = fields.iter().fold(0usize, |acc, f| {
        acc.saturating_add(f.name.len())
            .saturating_add(f.value.len())
            .saturating_add(32)
    });
    assert!(
        size <= limit,
        "{what}: decoded {} fields totalling {size} bytes with a cap of {limit}",
        fields.len()
    );
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let payload = &data[3..];
    let split = (u16::from_le_bytes([data[0], data[1]]) as usize).min(payload.len());
    let (a, b) = payload.split_at(split);
    let table = TABLE_SIZES[(data[2] & 7) as usize];
    let limit = LIST_LIMITS[((data[2] >> 4) & 7) as usize];

    let mut hpack = HpackDecoder::with_limits(table, limit);
    for block in [a, b] {
        match hpack.decode(block) {
            Ok(fields) => check("hpack", &fields, limit),
            // An error is fatal to the connection's compression context.
            Err(_) => break,
        }
    }

    let mut qpack = QpackDecoder::with_limits(table, limit);
    // Only the Result matters here; the Ok payload is ignored on purpose.
    // A failed feed leaves the instructions before the bad one applied, and
    // decoding against that table must still be safe.
    let _ = qpack.feed_encoder_stream(a).map(|_| ());
    if let Ok(fields) = qpack.decode_field_section(b) {
        check("qpack", &fields, limit);
    }
});
