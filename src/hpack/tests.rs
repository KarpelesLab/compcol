//! RFC 7541 Appendix C worked-example vectors + round-trip / error tests.

use super::*;
use alloc::vec;

fn f(name: &[u8], value: &[u8]) -> HeaderField {
    HeaderField::new(name, value)
}

/// RFC 7541 C.3 — request sequence WITHOUT Huffman. Asserts byte-exact
/// encoding (with the dynamic table evolving across the three blocks) and
/// that a decoder reproduces the field lists.
#[test]
fn rfc_c3_request_sequence_raw() {
    let mut enc = HpackEncoder::new();
    enc.set_huffman(false);
    let mut dec = HpackDecoder::new();

    // C.3.1
    let req1 = [
        f(b":method", b"GET"),
        f(b":scheme", b"http"),
        f(b":path", b"/"),
        f(b":authority", b"www.example.com"),
    ];
    let b1 = enc.encode(&req1);
    assert_eq!(
        b1,
        [
            0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65, 0x78, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d
        ]
    );
    assert_eq!(dec.decode(&b1).unwrap(), req1);

    // C.3.2
    let req2 = [
        f(b":method", b"GET"),
        f(b":scheme", b"http"),
        f(b":path", b"/"),
        f(b":authority", b"www.example.com"),
        f(b"cache-control", b"no-cache"),
    ];
    let b2 = enc.encode(&req2);
    assert_eq!(
        b2,
        [
            0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63, 0x61, 0x63, 0x68, 0x65
        ]
    );
    assert_eq!(dec.decode(&b2).unwrap(), req2);

    // C.3.3
    let req3 = [
        f(b":method", b"GET"),
        f(b":scheme", b"https"),
        f(b":path", b"/index.html"),
        f(b":authority", b"www.example.com"),
        f(b"custom-key", b"custom-value"),
    ];
    let b3 = enc.encode(&req3);
    assert_eq!(
        b3,
        [
            0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b,
            0x65, 0x79, 0x0c, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75,
            0x65
        ]
    );
    assert_eq!(dec.decode(&b3).unwrap(), req3);
}

/// RFC 7541 C.4 — the same request sequence WITH Huffman string coding.
#[test]
fn rfc_c4_request_sequence_huffman() {
    let mut enc = HpackEncoder::new(); // Huffman on by default
    let mut dec = HpackDecoder::new();

    let req1 = [
        f(b":method", b"GET"),
        f(b":scheme", b"http"),
        f(b":path", b"/"),
        f(b":authority", b"www.example.com"),
    ];
    let b1 = enc.encode(&req1);
    assert_eq!(
        b1,
        [
            0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab,
            0x90, 0xf4, 0xff
        ]
    );
    assert_eq!(dec.decode(&b1).unwrap(), req1);

    let req2 = [
        f(b":method", b"GET"),
        f(b":scheme", b"http"),
        f(b":path", b"/"),
        f(b":authority", b"www.example.com"),
        f(b"cache-control", b"no-cache"),
    ];
    let b2 = enc.encode(&req2);
    assert_eq!(
        b2,
        [0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]
    );
    assert_eq!(dec.decode(&b2).unwrap(), req2);

    let req3 = [
        f(b":method", b"GET"),
        f(b":scheme", b"https"),
        f(b":path", b"/index.html"),
        f(b":authority", b"www.example.com"),
        f(b"custom-key", b"custom-value"),
    ];
    let b3 = enc.encode(&req3);
    assert_eq!(
        b3,
        [
            0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f,
            0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf
        ]
    );
    assert_eq!(dec.decode(&b3).unwrap(), req3);
}

/// Dynamic-table eviction at a small bound (the scenario RFC 7541 C.5/C.6
/// exercise): each response entry is ~63–98 bytes, so a 256-byte table holds
/// at most a few. Verified behaviorally through a shared encoder/decoder.
#[test]
fn eviction_at_table_size_256() {
    let mut enc = HpackEncoder::with_max_table_size(256);
    let mut dec = HpackDecoder::with_max_table_size(256);

    let resp = [
        f(b":status", b"302"),
        f(b"cache-control", b"private"),
        f(b"date", b"Mon, 21 Oct 2013 20:13:21 GMT"),
        f(b"location", b"https://www.example.com"),
    ];
    let block = enc.encode(&resp);
    // First byte is the queued size update (001 prefix → 0x3f continuation
    // since 256 > 31): 0x3f 0xe1 0x01.
    assert_eq!(&block[..3], &[0x3f, 0xe1, 0x01]);
    assert_eq!(dec.decode(&block).unwrap(), resp);
    assert_eq!(dec.table_max_size(), 256);

    // A second, identical response must still round-trip after eviction
    // churn (entries indexed from the dynamic table where they survived).
    let block2 = enc.encode(&resp);
    assert_eq!(dec.decode(&block2).unwrap(), resp);
}

#[test]
fn round_trip_many_fields() {
    let mut enc = HpackEncoder::new();
    let mut dec = HpackDecoder::new();
    let fields: vec::Vec<HeaderField> = (0..50)
        .map(|i| {
            let name = alloc::format!("x-header-{i}");
            let val = alloc::format!("value-{}-{}", i, "blahblah".repeat(i % 4));
            f(name.as_bytes(), val.as_bytes())
        })
        .collect();
    let block = enc.encode(&fields);
    assert_eq!(dec.decode(&block).unwrap(), fields);
}

#[test]
fn sensitive_field_never_indexed() {
    let mut enc = HpackEncoder::new();
    let mut dec = HpackDecoder::new();
    let fields = [HeaderField::sensitive(b"authorization", b"secret-token")];
    let block = enc.encode(&fields);
    // 0001 pattern with name index 23 (authorization) → 0x10 | 23 = 0x1f...
    // (23 < 15? no: 4-bit prefix max is 15, so 0x1f then continuation 0x08).
    assert_eq!(block[0], 0x1f);
    let out = dec.decode(&block).unwrap();
    assert_eq!(out, fields);
    assert!(out[0].sensitive);
}

#[test]
fn decode_rejects_bad_index() {
    let mut dec = HpackDecoder::new();
    // Indexed header field, index 0 → invalid.
    assert!(matches!(dec.decode(&[0x80]), Err(Error::Corrupt)));
    // Indexed header field, index 99 (no such dynamic entry) → invalid.
    assert!(matches!(dec.decode(&[0xe3]), Err(Error::Corrupt)));
}

#[test]
fn decode_rejects_oversized_size_update() {
    let mut dec = HpackDecoder::with_max_table_size(256);
    // Size update to 4096 (> 256 connection limit): 0x3f 0xe1 0x1f.
    assert!(matches!(
        dec.decode(&[0x3f, 0xe1, 0x1f]),
        Err(Error::Corrupt)
    ));
}

#[test]
fn decode_rejects_truncated_string() {
    let mut dec = HpackDecoder::new();
    // Literal, new name, length 5 but only 2 bytes follow.
    assert!(matches!(
        dec.decode(&[0x40, 0x05, b'a', b'b']),
        Err(Error::UnexpectedEnd)
    ));
}
