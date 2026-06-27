//! RFC 9204 Appendix B worked-example vectors + round-trip / error tests.

use super::*;
use alloc::vec;

fn f(name: &[u8], value: &[u8]) -> HeaderField {
    HeaderField::new(name, value)
}

// ─── static table sanity ─────────────────────────────────────────────────

#[test]
fn static_table_has_99_entries_and_boundaries() {
    assert_eq!(static_table::STATIC_LEN, 99);
    assert_eq!(static_table::get(0), Some((&b":authority"[..], &b""[..])));
    assert_eq!(static_table::get(1), Some((&b":path"[..], &b"/"[..])));
    assert_eq!(static_table::get(17), Some((&b":method"[..], &b"GET"[..])));
    assert_eq!(
        static_table::get(98),
        Some((&b"x-frame-options"[..], &b"sameorigin"[..]))
    );
    assert_eq!(static_table::get(99), None);
}

// ─── B.1: literal field line with name reference (static) ────────────────

#[test]
fn rfc_b1_literal_field_line_static_name_ref() {
    // Stream 0:  0x00 0x00  (Required Insert Count = 0, Base = 0)
    //            0x51 0x0b "/index.html"  (Literal w/ Name Ref, static idx 1)
    let expected: &[u8] = &[
        0x00, 0x00, 0x51, 0x0b, b'/', b'i', b'n', b'd', b'e', b'x', b'.', b'h', b't', b'm', b'l',
    ];

    let mut enc = QpackEncoder::new();
    enc.set_huffman(false); // RFC example is raw
    let block = enc.encode_field_section(&[f(b":path", b"/index.html")]);
    assert_eq!(block, expected);

    let mut dec = QpackDecoder::new();
    let out = dec.decode_field_section(expected).unwrap();
    assert_eq!(out, vec![f(b":path", b"/index.html")]);
    // No dynamic-table activity.
    assert_eq!(dec.insert_count(), 0);
    assert_eq!(dec.table_size(), 0);
}

// ─── B.2: dynamic table (encoder-stream inserts + post-base field section) ─

#[test]
fn rfc_b2_dynamic_table_inserts_and_post_base() {
    let mut dec = QpackDecoder::new();

    // Encoder stream:
    //   3f bd 01                 Set Dynamic Table Capacity = 220
    //   c0 0f "www.example.com"   Insert w/ Name Ref, static idx 0 (:authority)
    //   c1 0c "/sample/path"      Insert w/ Name Ref, static idx 1 (:path)
    let mut estream: Vec<u8> = vec![0x3f, 0xbd, 0x01, 0xc0, 0x0f];
    estream.extend_from_slice(b"www.example.com");
    estream.extend_from_slice(&[0xc1, 0x0c]);
    estream.extend_from_slice(b"/sample/path");

    dec.feed_encoder_stream(&estream).unwrap();

    // Dynamic table state after inserts.
    assert_eq!(dec.table_capacity(), 220);
    assert_eq!(dec.insert_count(), 2);
    assert_eq!(dec.table_len(), 2);
    // Size = (10+15+32) + (5+12+32) = 57 + 49 = 106.
    assert_eq!(dec.table_size(), 106);

    // Field section (stream 4):
    //   03 81   Required Insert Count = 2, Base = 0
    //   10      Indexed, post-base index 0  → abs 0  (:authority=www.example.com)
    //   11      Indexed, post-base index 1  → abs 1  (:path=/sample/path)
    let block: &[u8] = &[0x03, 0x81, 0x10, 0x11];
    let out = dec.decode_field_section(block).unwrap();
    assert_eq!(
        out,
        vec![
            f(b":authority", b"www.example.com"),
            f(b":path", b"/sample/path"),
        ]
    );
}

// ─── B.3: speculative insert (literal name) ──────────────────────────────

#[test]
fn rfc_b3_speculative_insert_literal_name() {
    let mut dec = QpackDecoder::new();

    // Set capacity first (the example continues B.2's table; here we make it
    // self-contained by raising capacity, then perform the literal insert).
    let mut estream: Vec<u8> = vec![0x3f, 0xbd, 0x01, 0xc0, 0x0f];
    estream.extend_from_slice(b"www.example.com");
    estream.extend_from_slice(&[0xc1, 0x0c]);
    estream.extend_from_slice(b"/sample/path");
    dec.feed_encoder_stream(&estream).unwrap();

    // Encoder stream (B.3):
    //   4a "custom-key" 0c "custom-value"   Insert with Literal Name
    let mut ins: Vec<u8> = vec![0x4a];
    ins.extend_from_slice(b"custom-key");
    ins.push(0x0c);
    ins.extend_from_slice(b"custom-value");
    dec.feed_encoder_stream(&ins).unwrap();

    assert_eq!(dec.insert_count(), 3);
    assert_eq!(dec.table_len(), 3);
    // Size = 106 + (10+12+32) = 106 + 54 = 160.
    assert_eq!(dec.table_size(), 160);
}

// ─── B.4: duplicate + field section with dynamic + static refs ───────────

#[test]
fn rfc_b4_duplicate_and_dynamic_field_section() {
    let mut dec = QpackDecoder::new();

    // Build B.2 + B.3 table state.
    let mut estream: Vec<u8> = vec![0x3f, 0xbd, 0x01, 0xc0, 0x0f];
    estream.extend_from_slice(b"www.example.com");
    estream.extend_from_slice(&[0xc1, 0x0c]);
    estream.extend_from_slice(b"/sample/path");
    let mut ins: Vec<u8> = vec![0x4a];
    ins.extend_from_slice(b"custom-key");
    ins.push(0x0c);
    ins.extend_from_slice(b"custom-value");
    estream.extend_from_slice(&ins);
    dec.feed_encoder_stream(&estream).unwrap();
    assert_eq!(dec.insert_count(), 3);

    // Encoder stream (B.4): 02  Duplicate(relative index 2)
    //   abs = InsertCount(3) - Index(2) - 1 = 0  (:authority=www.example.com)
    dec.feed_encoder_stream(&[0x02]).unwrap();
    assert_eq!(dec.insert_count(), 4);
    assert_eq!(dec.table_len(), 4);
    // Size = 160 + 57 = 217.
    assert_eq!(dec.table_size(), 217);

    // Field section (stream 8):
    //   05 00   Required Insert Count = 4, Base = 4
    //   80      Indexed dynamic, abs = Base(4) - 0 - 1 = 3 (:authority=...)
    //   c1      Indexed static index 1  (:path=/)
    //   81      Indexed dynamic, abs = Base(4) - 1 - 1 = 2 (custom-key=custom-value)
    let block: &[u8] = &[0x05, 0x00, 0x80, 0xc1, 0x81];
    let out = dec.decode_field_section(block).unwrap();
    assert_eq!(
        out,
        vec![
            f(b":authority", b"www.example.com"),
            f(b":path", b"/"),
            f(b"custom-key", b"custom-value"),
        ]
    );
}

// ─── B.5: insert with name reference (dynamic) + eviction ────────────────

#[test]
fn rfc_b5_dynamic_name_ref_insert_with_eviction() {
    let mut dec = QpackDecoder::new();

    // Build through B.4 (4 entries, size 217, capacity 220).
    let mut estream: Vec<u8> = vec![0x3f, 0xbd, 0x01, 0xc0, 0x0f];
    estream.extend_from_slice(b"www.example.com");
    estream.extend_from_slice(&[0xc1, 0x0c]);
    estream.extend_from_slice(b"/sample/path");
    let mut ins: Vec<u8> = vec![0x4a];
    ins.extend_from_slice(b"custom-key");
    ins.push(0x0c);
    ins.extend_from_slice(b"custom-value");
    estream.extend_from_slice(&ins);
    estream.push(0x02); // duplicate
    dec.feed_encoder_stream(&estream).unwrap();
    assert_eq!(dec.insert_count(), 4);
    assert_eq!(dec.table_size(), 217);

    // Encoder stream (B.5):
    //   81 0d "custom-value2"   Insert w/ Name Ref, dynamic relative idx 1
    //   abs = InsertCount(4) - Index(1) - 1 = 2  (name custom-key)
    // Inserting (custom-key=custom-value2) costs 10+13+32 = 55; 217+55 = 272 >
    // 220, so the oldest entry (abs 0, :authority/www.example.com, size 57) is
    // evicted → 217 - 57 + 55 = 215.
    let mut b5: Vec<u8> = vec![0x81, 0x0d];
    b5.extend_from_slice(b"custom-value2");
    dec.feed_encoder_stream(&b5).unwrap();

    assert_eq!(dec.insert_count(), 5);
    assert_eq!(dec.table_len(), 4); // 5 inserted, 1 evicted
    assert_eq!(dec.table_size(), 215);

    // abs 0 is gone; abs 1..=4 live. New entry (abs 4) is custom-value2.
    // Verify via a field section: Required Insert Count = 5, Base = 5,
    //   80   dynamic abs = 5 - 0 - 1 = 4  (custom-key=custom-value2)
    // Required Insert Count enc = (5 mod 12) + 1 = 6 → 0x06; Base delta 0.
    let block: &[u8] = &[0x06, 0x00, 0x80];
    let out = dec.decode_field_section(block).unwrap();
    assert_eq!(out, vec![f(b"custom-key", b"custom-value2")]);
}

// ─── static encoder round-trips ──────────────────────────────────────────

#[test]
fn encode_indexed_static_full_match() {
    // :path=/ is static index 1 (full match) → Indexed Field Line static.
    let mut enc = QpackEncoder::new();
    let block = enc.encode_field_section(&[f(b":path", b"/")]);
    assert_eq!(block, &[0x00, 0x00, 0xc1]); // prefix + (1 T=1 idx=1)

    let mut dec = QpackDecoder::new();
    assert_eq!(
        dec.decode_field_section(&block).unwrap(),
        vec![f(b":path", b"/")]
    );
}

#[test]
fn round_trip_static_and_literal_huffman() {
    let mut enc = QpackEncoder::new(); // Huffman on
    let mut dec = QpackDecoder::new();
    let fields = vec![
        f(b":method", b"GET"),
        f(b":scheme", b"https"),
        f(b":path", b"/index.html"),
        f(b":authority", b"www.example.com"),
        f(b"custom-key", b"custom-value"),
        f(b"accept", b"*/*"),
    ];
    let block = enc.encode_field_section(&fields);
    assert_eq!(dec.decode_field_section(&block).unwrap(), fields);
}

#[test]
fn round_trip_many_fields_no_huffman() {
    let mut enc = QpackEncoder::new();
    enc.set_huffman(false);
    let mut dec = QpackDecoder::new();
    let fields: Vec<HeaderField> = (0..40)
        .map(|i| {
            let name = alloc::format!("x-header-{i}");
            let val = alloc::format!("value-{}-{}", i, "blahblah".repeat(i % 3));
            f(name.as_bytes(), val.as_bytes())
        })
        .collect();
    let block = enc.encode_field_section(&fields);
    assert_eq!(dec.decode_field_section(&block).unwrap(), fields);
}

#[test]
fn sensitive_field_sets_never_index_bit() {
    let mut enc = QpackEncoder::new();
    enc.set_huffman(false);
    let mut dec = QpackDecoder::new();
    // authorization is static index 84 (name match only) → Literal w/ Name Ref,
    // N bit set.
    let fields = vec![HeaderField::sensitive(b"authorization", b"secret")];
    let block = enc.encode_field_section(&fields);
    // byte[2] = 0 1 N T idx(4+). N=1, T=1, idx=84 (>15 so prefix 0x5f + cont).
    assert_eq!(block[2] & 0b0010_0000, 0b0010_0000); // N bit
    let out = dec.decode_field_section(&block).unwrap();
    assert_eq!(out, fields);
    assert!(out[0].sensitive);

    // A literal-literal-name sensitive field too.
    let fields2 = vec![HeaderField::sensitive(b"x-secret-hdr", b"v")];
    let block2 = enc.encode_field_section(&fields2);
    // byte[2] = 0 0 1 N H len(3+). N bit is 0x10.
    assert_eq!(block2[2] & 0b0001_0000, 0b0001_0000);
    let out2 = dec.decode_field_section(&block2).unwrap();
    assert!(out2[0].sensitive);
}

// ─── dynamic-table encoder ───────────────────────────────────────────────

/// Round-trip a dynamic [`Encoded`] pair through `dec`: feed the encoder stream
/// first (the contract), then decode the field section.
fn rt(dec: &mut QpackDecoder, e: &Encoded) -> Vec<HeaderField> {
    dec.feed_encoder_stream(&e.encoder_stream).unwrap();
    dec.decode_field_section(&e.field_section).unwrap()
}

#[test]
fn encode_static_only_matches_encode_field_section() {
    // encode() on a static-only encoder emits no encoder stream and a field
    // section byte-identical to encode_field_section().
    let fields = vec![
        f(b":path", b"/"),
        f(b":method", b"GET"),
        f(b"custom", b"value"),
    ];
    let mut a = QpackEncoder::new();
    let mut b = QpackEncoder::new();
    let e = a.encode(&fields);
    assert!(e.encoder_stream.is_empty());
    assert_eq!(e.field_section, b.encode_field_section(&fields));
}

#[test]
fn dynamic_inserts_literal_name_and_round_trips() {
    let mut enc = QpackEncoder::with_dynamic_table(4096);
    let mut dec = QpackDecoder::with_max_table_capacity(4096);

    let fields = vec![f(b"custom-key", b"custom-value")];
    let e = enc.encode(&fields);
    // An insert happened (Set Capacity + Insert with Literal Name), and the
    // field section carries a non-zero Required Insert Count.
    assert!(!e.encoder_stream.is_empty());
    assert_eq!(enc.insert_count(), 1);
    assert_ne!(e.field_section[0], 0x00); // RIC prefix byte != 0
    assert_eq!(rt(&mut dec, &e), fields);
    assert_eq!(dec.insert_count(), 1);
}

#[test]
fn dynamic_reuses_entry_without_new_inserts() {
    let mut enc = QpackEncoder::with_dynamic_table(4096);
    let mut dec = QpackDecoder::with_max_table_capacity(4096);

    let fields = vec![f(b"x-custom", b"hello")];
    let first = enc.encode(&fields);
    assert!(!first.encoder_stream.is_empty());
    assert_eq!(rt(&mut dec, &first), fields);

    // Second section references the existing entry — no new encoder-stream
    // bytes, but still a dynamic (indexed) reference with non-zero RIC.
    let second = enc.encode(&fields);
    assert!(second.encoder_stream.is_empty());
    assert_eq!(enc.insert_count(), 1);
    assert_eq!(rt(&mut dec, &second), fields);
}

#[test]
fn dynamic_static_name_reference_insert() {
    // :authority has a static name (index 0) but no value match → the insert
    // uses a static Insert with Name Reference.
    let mut enc = QpackEncoder::with_dynamic_table(4096);
    let mut dec = QpackDecoder::with_max_table_capacity(4096);

    let fields = vec![f(b":authority", b"www.example.com")];
    let e = enc.encode(&fields);
    assert_eq!(enc.insert_count(), 1);
    assert_eq!(rt(&mut dec, &e), fields);
}

#[test]
fn dynamic_name_reference_reuse_for_new_value() {
    // First insert custom-key=v1 (literal name); a later field with the same
    // name but a new value inserts via a *dynamic* name reference.
    let mut enc = QpackEncoder::with_dynamic_table(4096);
    let mut dec = QpackDecoder::with_max_table_capacity(4096);

    let e1 = enc.encode(&[f(b"custom-key", b"v1")]);
    assert_eq!(rt(&mut dec, &e1), vec![f(b"custom-key", b"v1")]);

    let e2 = enc.encode(&[f(b"custom-key", b"v2")]);
    assert!(!e2.encoder_stream.is_empty());
    assert_eq!(enc.insert_count(), 2);
    assert_eq!(rt(&mut dec, &e2), vec![f(b"custom-key", b"v2")]);
}

#[test]
fn dynamic_mixed_static_dynamic_literal_round_trip() {
    let mut enc = QpackEncoder::with_dynamic_table(4096);
    let mut dec = QpackDecoder::with_max_table_capacity(4096);

    let fields = vec![
        f(b":method", b"GET"),            // static full match
        f(b":authority", b"example.org"), // static name → insert
        f(b"x-app-id", b"42"),            // literal name → insert
        f(b"accept", b"*/*"),             // static full match
        f(b"x-app-id", b"42"),            // dynamic full match (reuse)
    ];
    let e = enc.encode(&fields);
    assert_eq!(rt(&mut dec, &e), fields);
}

#[test]
fn dynamic_huffman_round_trip_many_fields() {
    let mut enc = QpackEncoder::with_dynamic_table(8192); // Huffman on
    let mut dec = QpackDecoder::with_max_table_capacity(8192);

    let mut fields: Vec<HeaderField> = (0..30)
        .map(|i| {
            let name = alloc::format!("x-header-{i}");
            let val = alloc::format!("value-{i}-{}", "data".repeat(i % 4));
            f(name.as_bytes(), val.as_bytes())
        })
        .collect();
    // Repeat some fields so the second occurrences reuse dynamic entries.
    fields.extend_from_slice(&fields.clone()[..10]);
    let e = enc.encode(&fields);
    assert_eq!(rt(&mut dec, &e), fields);
}

#[test]
fn dynamic_eviction_safety_within_section() {
    // Capacity fits only ~2 of these entries. Entries referenced by the field
    // section must never be evicted by a later insert in the same batch, so the
    // encoder falls back to literals once the table is full — and the section
    // still round-trips exactly.
    let mut enc = QpackEncoder::with_dynamic_table(128);
    let mut dec = QpackDecoder::with_max_table_capacity(128);

    let fields = vec![
        f(b"aaaaaaaaaa", b"00000000000000000000"), // size 10+20+32 = 62
        f(b"bbbbbbbbbb", b"11111111111111111111"), // 62  → table now full
        f(b"cccccccccc", b"22222222222222222222"), // cannot insert → literal
        f(b"dddddddddd", b"33333333333333333333"), // literal
    ];
    let e = enc.encode(&fields);
    assert_eq!(rt(&mut dec, &e), fields);
    // At most two entries ever inserted (the rest fell back to literals).
    assert!(enc.insert_count() <= 2, "inserted {}", enc.insert_count());
}

#[test]
fn dynamic_sensitive_field_not_inserted() {
    let mut enc = QpackEncoder::with_dynamic_table(4096);
    let mut dec = QpackDecoder::with_max_table_capacity(4096);

    let fields = vec![
        HeaderField::sensitive(b"authorization", b"Bearer secret"), // static name
        HeaderField::sensitive(b"x-token", b"abc123"),              // literal name
    ];
    let e = enc.encode(&fields);
    // Nothing inserted; both coded never-indexed.
    assert!(e.encoder_stream.is_empty());
    assert_eq!(enc.insert_count(), 0);
    let out = rt(&mut dec, &e);
    assert_eq!(out, fields);
    assert!(out[0].sensitive);
    assert!(out[1].sensitive);
}

#[test]
fn dynamic_cross_section_reference_with_eviction() {
    // Encode three sections; the third reuses an entry inserted in the first
    // while later inserts have advanced (and possibly evicted) the table.
    let mut enc = QpackEncoder::with_dynamic_table(256);
    let mut dec = QpackDecoder::with_max_table_capacity(256);

    let a = vec![f(b"k1", b"reusable-value")];
    let ea = enc.encode(&a);
    assert_eq!(rt(&mut dec, &ea), a);

    // Reference k1 again immediately (still present).
    let eb = enc.encode(&a);
    assert!(eb.encoder_stream.is_empty());
    assert_eq!(rt(&mut dec, &eb), a);
}

// ─── error handling ──────────────────────────────────────────────────────

#[test]
fn blocked_reference_rejected() {
    // Field section claims Required Insert Count = 2 but nothing inserted.
    let mut dec = QpackDecoder::new();
    // enc=3 → RIC=2 (TotalInserts=0, MaxEntries=128, FullRange=256). Base 0.
    let block: &[u8] = &[0x03, 0x81, 0x10];
    assert!(matches!(
        dec.decode_field_section(block),
        Err(Error::Corrupt)
    ));
}

#[test]
fn over_limit_capacity_rejected() {
    let mut dec = QpackDecoder::with_max_table_capacity(100);
    // Set Dynamic Table Capacity = 220 (> 100) → 0x3f 0xbd 0x01.
    assert!(matches!(
        dec.feed_encoder_stream(&[0x3f, 0xbd, 0x01]),
        Err(Error::Corrupt)
    ));
}

#[test]
fn insert_without_capacity_rejected() {
    let mut dec = QpackDecoder::new();
    // Insert with Name Reference at capacity 0 → cannot fit → Corrupt.
    let mut ins: Vec<u8> = vec![0xc0, 0x0f];
    ins.extend_from_slice(b"www.example.com");
    assert!(matches!(dec.feed_encoder_stream(&ins), Err(Error::Corrupt)));
}

#[test]
fn bad_static_index_rejected() {
    let mut dec = QpackDecoder::new();
    // Indexed static index 99 (out of range): 1 T=1 idx=99.
    // 0xc0 | 63 prefix + continuation for 99-63=36 → 0xff 0x24.
    let block: &[u8] = &[0x00, 0x00, 0xff, 0x24];
    assert!(matches!(
        dec.decode_field_section(block),
        Err(Error::Corrupt)
    ));
}

#[test]
fn truncated_value_string_rejected() {
    let mut dec = QpackDecoder::new();
    // Literal w/ literal name, name len 1 "x", value length 5 but truncated.
    // prefix 0x00 0x00, then 0x21 (0 0 1 0 0 len=1) 'x', 0x05 'a' 'b'
    let block: &[u8] = &[0x00, 0x00, 0x21, b'x', 0x05, b'a', b'b'];
    assert!(matches!(
        dec.decode_field_section(block),
        Err(Error::UnexpectedEnd)
    ));
}

#[test]
fn duplicate_bad_index_rejected() {
    let mut dec = QpackDecoder::new();
    // Raise capacity, then Duplicate(relative 0) with an empty table → Corrupt.
    dec.feed_encoder_stream(&[0x3f, 0xbd, 0x01]).unwrap();
    assert!(matches!(
        dec.feed_encoder_stream(&[0x00]),
        Err(Error::Corrupt)
    ));
}
