//! Streaming round-trip + decoder-fixture tests for Amiga LZX.
//!
//! The encoder in this build only emits uncompressed BLOCKTYPE=3 blocks, so
//! the round-trip tests exercise:
//!   - The 4-byte standalone stream header (LE total uncompressed length).
//!   - The LZX 16-bit-LE-MSB-first bit reader on uncompressed-block headers.
//!   - The R0/R1/R2 dump and word-aligned raw payload path on the decoder side.
//!
//! The verbatim-block decoder is exercised through a hand-built fixture
//! ([`fixture_verbatim_decoder_only`]) since the encoder cannot produce
//! verbatim blocks itself.

#![cfg(feature = "amiga_lzx")]

use compcol::amiga_lzx::{AmigaLzx, Decoder, Encoder};
use compcol::{Algorithm, Decoder as _, Encoder as _, Error, Status};

// ─── small chunked-IO helpers ────────────────────────────────────────────

fn encode_chunked(input: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut enc = Encoder::new();
    let mut encoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < input.len() {
        let end = (i + in_chunk).min(input.len());
        let chunk = &input[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = enc.encode(&chunk[consumed..], &mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }

    loop {
        let (p, status) = enc.finish(&mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("encoder finish stalled");
                }
            }
        }
    }
    encoded
}

fn decode_chunked(encoded: &[u8], in_chunk: usize, out_chunk: usize) -> Vec<u8> {
    let mut dec = Decoder::new();
    let mut decoded = Vec::new();
    let mut buf = vec![0u8; out_chunk.max(1)];
    let mut i = 0;

    while i < encoded.len() {
        let end = (i + in_chunk).min(encoded.len());
        let chunk = &encoded[i..end];
        let mut consumed = 0;
        while consumed < chunk.len() {
            let (p, status) = dec.decode(&chunk[consumed..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            consumed += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        i = end;
    }

    loop {
        let (p, status) = dec.finish(&mut buf).unwrap();
        decoded.extend_from_slice(&buf[..p.written]);
        match status {
            Status::StreamEnd => break,
            Status::OutputFull | Status::InputEmpty => {
                if p.written == 0 {
                    panic!("decoder finish stalled (decoded {} so far)", decoded.len());
                }
            }
        }
    }
    decoded
}

fn round_trip(input: &[u8]) {
    let encoded = encode_chunked(input, input.len().max(1), input.len().max(64) * 2 + 64);
    let decoded = decode_chunked(&encoded, encoded.len().max(1), input.len().max(1));
    assert_eq!(decoded, input, "round-trip mismatch");
}

// ─── identity ────────────────────────────────────────────────────────────

#[test]
fn name_is_amiga_lzx() {
    assert_eq!(<AmigaLzx as Algorithm>::NAME, "amiga_lzx");
}

// ─── empty + small inputs ────────────────────────────────────────────────

#[test]
fn round_trip_empty() {
    round_trip(&[]);
}

#[test]
fn round_trip_single_byte() {
    round_trip(&[0x42]);
}

#[test]
fn round_trip_hello() {
    round_trip(b"hello, world!");
}

#[test]
fn round_trip_two_bytes() {
    round_trip(&[0xAA, 0xBB]);
}

// ─── larger payloads ─────────────────────────────────────────────────────

fn lorem(target_bytes: usize) -> Vec<u8> {
    let base: &[u8] = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit, \
        sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. ";
    let mut out = Vec::with_capacity(target_bytes + base.len());
    while out.len() < target_bytes {
        out.extend_from_slice(base);
    }
    out.truncate(target_bytes);
    out
}

#[test]
fn round_trip_lorem_4kib() {
    round_trip(&lorem(4 * 1024));
}

#[test]
fn round_trip_64kib_window_boundary() {
    // 64 KiB hits the Amiga LZX fixed window size exactly. The repeating
    // pattern would back-reference across the window if the encoder used
    // matches; here the test simply makes sure two adjacent 32 KiB
    // uncompressed blocks round-trip across the window-size boundary.
    let mut data = Vec::with_capacity(64 * 1024);
    let chunk: &[u8] = b"AmigaLZX/64KiB/window-boundary;";
    while data.len() < 64 * 1024 {
        data.extend_from_slice(chunk);
    }
    data.truncate(64 * 1024);
    round_trip(&data);
}

#[test]
fn round_trip_pseudorandom_256kib() {
    let mut data = Vec::with_capacity(256 * 1024);
    let mut x: u32 = 0xCAFE_BABE;
    while data.len() < 256 * 1024 {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        data.push((x >> 16) as u8);
    }
    round_trip(&data);
}

#[test]
fn round_trip_mixed_corpus() {
    // Lorem-style + binary noise + zero run, all in one buffer; large enough
    // to span multiple 32 KiB encoder chunks.
    let mut data = Vec::new();
    data.extend_from_slice(&lorem(20 * 1024));
    data.extend(core::iter::repeat_n(0u8, 8 * 1024));
    let mut x: u32 = 0xDEAD_BEEF;
    for _ in 0..(40 * 1024) {
        x = x.wrapping_mul(1103515245).wrapping_add(12345);
        data.push((x >> 16) as u8);
    }
    data.extend_from_slice(&lorem(10 * 1024));
    round_trip(&data);
}

// ─── streaming ───────────────────────────────────────────────────────────

#[test]
fn one_byte_streaming_round_trip() {
    let input = b"streaming, one byte at a time, both directions.".to_vec();
    let encoded = encode_chunked(&input, 1, 1);
    let decoded = decode_chunked(&encoded, 1, 1);
    assert_eq!(decoded, input);
}

// ─── reset ───────────────────────────────────────────────────────────────

#[test]
fn encoder_reset_round_trip() {
    let mut enc = Encoder::new();
    let mut buf = vec![0u8; 1024];

    for input in [b"abc".as_ref(), b"defgh".as_ref(), b"".as_ref()] {
        enc.reset();
        let mut encoded = Vec::new();
        let (p, _status) = enc.encode(input, &mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        assert_eq!(p.consumed, input.len());
        loop {
            let (p, status) = enc.finish(&mut buf).unwrap();
            encoded.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }
        let decoded = decode_chunked(&encoded, encoded.len().max(1), 1024);
        assert_eq!(decoded, input);
    }
}

#[test]
fn decoder_reset_round_trip() {
    let mut dec = Decoder::new();
    for input in [b"abc".as_ref(), b"longer message here".as_ref()] {
        let encoded = encode_chunked(input, input.len().max(1), 1024);
        dec.reset();
        let mut decoded = Vec::new();
        let mut buf = vec![0u8; 1024];
        let mut i = 0;
        while i < encoded.len() {
            let (p, status) = dec.decode(&encoded[i..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            i += p.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        loop {
            let (p, status) = dec.finish(&mut buf).unwrap();
            decoded.extend_from_slice(&buf[..p.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }
        assert_eq!(decoded, input);
    }
}

// ─── error rejection ─────────────────────────────────────────────────────

#[test]
fn truncated_header() {
    // Only 2 bytes of the 4-byte LE length header — finish() must reject.
    let bad: &[u8] = &[0x10, 0x00];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let (p, _status) = dec.decode(bad, &mut out).unwrap();
    assert_eq!(p.consumed, 2);
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn truncated_stream_after_header() {
    // Valid 4-byte header declaring 10 bytes uncompressed; no payload.
    let header: &[u8] = &[10, 0, 0, 0];
    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    let (p, _status) = dec.decode(header, &mut out).unwrap();
    assert_eq!(p.consumed, 4);
    assert_eq!(p.written, 0);
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn truncated_block_payload() {
    // 4-byte header (total=4), then a block declaring BLOCK_SIZE=4 but
    // truncated mid-payload.
    let header: &[u8] = &[4, 0, 0, 0];
    // BLOCKTYPE=3 (uncompressed), BLOCK_SIZE=4 → 27-bit header padded with
    // 5 zero bits to two LE words. Then 12 R-bytes 0/0/0, then the first
    // two payload bytes only (instead of four).
    let header27: u32 = (3u32 << 24) | 4;
    let padded32 = header27 << 5;
    let w0 = ((padded32 >> 16) & 0xFFFF) as u16;
    let w1 = (padded32 & 0xFFFF) as u16;
    let mut bytes: Vec<u8> = Vec::new();
    bytes.extend_from_slice(header);
    bytes.push((w0 & 0xFF) as u8);
    bytes.push((w0 >> 8) as u8);
    bytes.push((w1 & 0xFF) as u8);
    bytes.push((w1 >> 8) as u8);
    for r in [0u32, 0, 0] {
        bytes.extend_from_slice(&r.to_le_bytes());
    }
    bytes.push(b'a');
    bytes.push(b'b');
    // Two more bytes would be needed to finish.

    let mut dec = Decoder::new();
    let mut out = [0u8; 16];
    // Feed everything we have. We may emit a partial output (2 bytes), but
    // finish() will reject because more is owed.
    let (_p, _status) = dec.decode(&bytes, &mut out).unwrap();
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

#[test]
fn invalid_block_type_zero() {
    // Header total=10, then a block with BLOCKTYPE=0. The Amiga bitstream
    // begins directly with the 3-bit BLOCKTYPE field (no leading flag bit).
    let mut bytes: Vec<u8> = vec![10, 0, 0, 0];
    // BLOCKTYPE = 0 in the high 3 bits, BLOCK_SIZE = 10 in the next 24 bits.
    // 27 bits + 5 zero pad → 32 bits split into two 16-bit MSB-first words.
    let header27: u32 = 10; // BLOCKTYPE = 0 means the BLOCK_SIZE bits are alone.
    let padded32 = header27 << 5;
    let w0 = ((padded32 >> 16) & 0xFFFF) as u16;
    let w1 = (padded32 & 0xFFFF) as u16;
    bytes.push((w0 & 0xFF) as u8);
    bytes.push((w0 >> 8) as u8);
    bytes.push((w1 & 0xFF) as u8);
    bytes.push((w1 >> 8) as u8);

    let mut dec = Decoder::new();
    let mut out = [0u8; 32];
    let res = dec.decode(&bytes, &mut out);
    assert_eq!(res, Err(Error::InvalidBlockType));
}

#[test]
fn invalid_block_type_four() {
    // BLOCKTYPE = 4 is also outside the 1..=3 legal range.
    let mut bytes: Vec<u8> = vec![10, 0, 0, 0];
    let header27: u32 = (4u32 << 24) | 10;
    let padded32 = header27 << 5;
    let w0 = ((padded32 >> 16) & 0xFFFF) as u16;
    let w1 = (padded32 & 0xFFFF) as u16;
    bytes.push((w0 & 0xFF) as u8);
    bytes.push((w0 >> 8) as u8);
    bytes.push((w1 & 0xFF) as u8);
    bytes.push((w1 >> 8) as u8);

    let mut dec = Decoder::new();
    let mut out = [0u8; 32];
    let res = dec.decode(&bytes, &mut out);
    assert_eq!(res, Err(Error::InvalidBlockType));
}

#[test]
fn header_lies_about_length() {
    // Header declares total = 100 bytes, but the block only contains 4.
    // finish() must reject because we can't reach the declared length.
    let mut bytes: Vec<u8> = vec![100, 0, 0, 0];
    let header27: u32 = (3u32 << 24) | 4;
    let padded32 = header27 << 5;
    let w0 = ((padded32 >> 16) & 0xFFFF) as u16;
    let w1 = (padded32 & 0xFFFF) as u16;
    bytes.push((w0 & 0xFF) as u8);
    bytes.push((w0 >> 8) as u8);
    bytes.push((w1 & 0xFF) as u8);
    bytes.push((w1 >> 8) as u8);
    for r in [0u32, 0, 0] {
        bytes.extend_from_slice(&r.to_le_bytes());
    }
    bytes.extend_from_slice(b"abcd");

    let mut dec = Decoder::new();
    let mut out = [0u8; 256];
    let (_p, _status) = dec.decode(&bytes, &mut out).unwrap();
    let err = dec.finish(&mut out).unwrap_err();
    assert_eq!(err, Error::UnexpectedEnd);
}

// ─── decoder fixture: hand-built uncompressed-block stream ──────────────

#[test]
fn fixture_uncompressed_block_layout() {
    // Encode "hi" (2 bytes) and verify the on-wire byte sequence.
    //   [02 00 00 00]                       framing header (LE u32 = 2)
    //   then the LZX bitstream:
    //     3 bits  BLOCKTYPE = 011 (uncompressed)
    //     24 bits BLOCK_SIZE = 2
    //     5 bits  zero pad to reach a 16-bit-word boundary
    //   = two 16-bit MSB-first words: 0x6000, 0x0040
    //   then 12 R-bytes = 00 00 00 00 00 00 00 00 00 00 00 00
    //   then payload "hi" = 0x68 0x69
    let encoded = encode_chunked(b"hi", 2, 64);
    let expected: &[u8] = &[
        0x02, 0, 0, 0, // framing header
        0x00, 0x60, // first LZX word (0x6000) on wire as LE
        0x40, 0x00, // second LZX word (0x0040)
        0x00, 0x00, 0x00, 0x00, // R0
        0x00, 0x00, 0x00, 0x00, // R1
        0x00, 0x00, 0x00, 0x00, // R2
        0x68, 0x69, // payload "hi"
    ];
    assert_eq!(encoded, expected);
}

#[test]
fn fixture_uncompressed_decoder_only() {
    // Decoder-only round trip against a stream we constructed by hand.
    let fixture: &[u8] = &[
        0x02, 0, 0, 0, 0x00, 0x60, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, b'h', b'i',
    ];
    let out = decode_chunked(fixture, 4, 4);
    assert_eq!(out, b"hi");
}

// ─── decoder fixture: hand-built verbatim block ─────────────────────────
//
// Validates the BLOCKTYPE=1 (verbatim) path even though our encoder cannot
// produce verbatim output. The stream decodes to a single 'X' byte. The bit
// layout is reasoned about in the module-level comment of this test; the
// MSB-first bit stream is packed into 16-bit little-endian words by the
// [`BitPacker`] helper below.

/// MSB-first into 16-bit-LE-on-the-wire bit packer. LZX feeds 16 bits per
/// word into the decoder; we accumulate into a u64 from the high end and
/// flush 16-bit words once enough bits are queued.
#[derive(Default)]
struct BitPacker {
    buf: Vec<u8>,
    acc: u64,
    nbits: u32,
}

impl BitPacker {
    fn push(&mut self, value: u32, bits: u32) {
        assert!(bits <= 32);
        if bits == 0 {
            return;
        }
        let mask = if bits == 32 {
            u32::MAX
        } else {
            (1u32 << bits) - 1
        };
        let value = value & mask;
        // Place into the high end of the accumulator below the existing bits.
        self.acc |= (value as u64) << (64 - self.nbits - bits);
        self.nbits += bits;
        while self.nbits >= 16 {
            let word = (self.acc >> 48) as u16;
            // Wire byte order: low byte of word first.
            self.buf.push((word & 0xFF) as u8);
            self.buf.push((word >> 8) as u8);
            self.acc <<= 16;
            self.nbits -= 16;
        }
    }

    fn finish(mut self) -> Vec<u8> {
        if self.nbits > 0 {
            // Pad with zero bits up to the next 16-bit word boundary.
            let pad = 16 - self.nbits;
            self.push(0, pad);
        }
        self.buf
    }
}

#[test]
fn fixture_verbatim_decoder_only() {
    // We build a single verbatim block that decodes to one byte 'X' (0x58 = 88).
    //
    // Outline of what we emit, in order:
    //   1. 3 bits BLOCKTYPE = 1 (verbatim)
    //   2. 24 bits BLOCK_SIZE = 1
    //   3. Pretree #1: 20 × 4-bit code lengths. We use a five-symbol code
    //      (syms 0, 1, 16, 17, 18 each of length 3); canonical codes are
    //        sym 0  → 000
    //        sym 1  → 001
    //        sym 16 → 010
    //        sym 17 → 011
    //        sym 18 → 100
    //   4. Pretree-coded main_lens[0..256]:
    //        - sym 18 + N=31 → 51 zeros (cursor 0..51)
    //        - sym 18 + N=17 → 37 zeros (cursor 51..88)
    //        - sym 16 → main_lens[88] = (0 - 16) mod 17 = 1 (cursor 89)
    //        - sym 1  → main_lens[89] = (1 - 1) mod 17 = 0 (cursor 90)
    //        - sym 18 + N=31 → 51 zeros (cursor 90..141)
    //        - sym 18 + N=31 → 51 zeros (cursor 141..192)
    //        - sym 18 + N=31 → 51 zeros (cursor 192..243)
    //        - sym 17 + N=9  → 13 zeros (cursor 243..256)
    //   5. Pretree #2: 20 × 4-bit code lengths. Two-symbol code (syms 17, 18
    //      each length 1); canonical codes: sym 17 → 0, sym 18 → 1.
    //   6. Pretree-coded main_lens[256..512] (all zeros, prev_len = 0):
    //        - 5 × (sym 18 + N=29) → 5 × 49 = 245 zeros
    //        - 1 × (sym 17 + N=7)  → 11 zeros
    //   7. Pretree #3 (LENGTH_TREE): 20 × 4-bit lengths. Single-symbol code
    //      sym 18 length 1 → code 0.
    //   8. Pretree-coded length_lens[..249] (all zeros):
    //        - 4 × (sym 18 + N=31) → 4 × 51 = 204 zeros
    //        - 1 × (sym 18 + N=25) → 45 zeros
    //   9. Block payload: one main-tree symbol = 88 (single-symbol main tree,
    //      sym 88 length 1 → code 0). One bit.
    let mut bp = BitPacker::default();

    // Block header.
    bp.push(1, 3); // BLOCKTYPE = 1 (verbatim)
    bp.push(1, 24); // BLOCK_SIZE = 1

    // Pretree #1 lengths (20 × 4 bits): nonzero at indices 0, 16, 17, 18.
    let mut pre1 = [0u8; 20];
    pre1[0] = 3;
    pre1[16] = 3;
    pre1[17] = 3;
    pre1[18] = 3;
    for &v in &pre1 {
        bp.push(v as u32, 4);
    }

    // Pre-tree #1 canonical codes (canonical-order: by length-then-symbol-id;
    // four length-3 codes assigned starting from 0):
    let p1_sym0: u32 = 0b000;
    let p1_sym16: u32 = 0b001;
    let p1_sym17: u32 = 0b010;
    let p1_sym18: u32 = 0b011;

    // Main pass 1 data (cursor 0..256).
    bp.push(p1_sym18, 3);
    bp.push(31, 5); // 51 zeros (0..51)
    bp.push(p1_sym18, 3);
    bp.push(17, 5); // 37 zeros (51..88)
    bp.push(p1_sym16, 3); // delta 16 at index 88 → length 1
    // prev_len for each pretree symbol comes from main_lens[cursor] (i.e.
    // the previous block's value at the same index, not a rolling
    // accumulator). Since this is the first block, main_lens starts at
    // all-zero, so a delta of 0 at index 89 yields length 0.
    bp.push(p1_sym0, 3); // delta 0 at index 89 → length 0
    bp.push(p1_sym18, 3);
    bp.push(31, 5); // 51 zeros (90..141)
    bp.push(p1_sym18, 3);
    bp.push(31, 5); // 51 zeros (141..192)
    bp.push(p1_sym18, 3);
    bp.push(31, 5); // 51 zeros (192..243)
    bp.push(p1_sym17, 3);
    bp.push(9, 4); // 13 zeros (243..256)

    // Pretree #2 lengths (20 × 4 bits): syms 17 and 18 each length 1.
    let mut pre2 = [0u8; 20];
    pre2[17] = 1;
    pre2[18] = 1;
    for &v in &pre2 {
        bp.push(v as u32, 4);
    }

    let p2_sym17: u32 = 0b0;
    let p2_sym18: u32 = 0b1;

    // Main pass 2 data (cursor 256..512 = 256 zeros).
    for _ in 0..5 {
        bp.push(p2_sym18, 1);
        bp.push(29, 5); // 49 zeros each, 5 × 49 = 245
    }
    bp.push(p2_sym17, 1);
    bp.push(7, 4); // 11 zeros, total = 256

    // Pretree #3 (LENGTH_TREE) lengths: sym 18 length 1.
    let mut pre3 = [0u8; 20];
    pre3[18] = 1;
    for &v in &pre3 {
        bp.push(v as u32, 4);
    }

    let p3_sym18: u32 = 0b0;

    // Length tree data (cursor 0..249 zeros).
    for _ in 0..4 {
        bp.push(p3_sym18, 1);
        bp.push(31, 5); // 51 zeros, 4 × 51 = 204
    }
    bp.push(p3_sym18, 1);
    bp.push(25, 5); // 45 zeros, total 249.

    // Block payload: one main-tree symbol = 88 ('X'). Single-symbol main
    // tree (sym 88 length 1) → code 0. One bit.
    bp.push(0, 1);

    let bitstream = bp.finish();

    // Prepend the 4-byte LE total length header (total = 1).
    let mut wire = vec![1u8, 0, 0, 0];
    wire.extend_from_slice(&bitstream);

    let out = decode_chunked(&wire, wire.len(), 16);
    assert_eq!(out, b"X");
}

// ─── factory ─────────────────────────────────────────────────────────────

#[cfg(feature = "factory")]
mod factory {
    use compcol::Status;
    use compcol::factory;

    #[test]
    fn lookup_known() {
        assert!(factory::encoder_by_name("amiga_lzx").is_some());
        assert!(factory::decoder_by_name("amiga_lzx").is_some());
    }

    #[test]
    fn names_contains_amiga_lzx() {
        assert!(factory::names().contains(&"amiga_lzx"));
    }

    #[test]
    fn boxed_round_trip() {
        // The encoder emits uncompressed blocks; round-trip via the boxed
        // trait objects to confirm the factory hooks up correctly.
        let mut enc = factory::encoder_by_name("amiga_lzx").unwrap();
        let mut dec = factory::decoder_by_name("amiga_lzx").unwrap();
        let input = b"factory round-trip";
        let mut buf = vec![0u8; 256];
        let mut encoded = Vec::new();
        let (p, _) = enc.encode(input, &mut buf).unwrap();
        encoded.extend_from_slice(&buf[..p.written]);
        assert_eq!(p.consumed, input.len());
        loop {
            let (pf, status) = enc.finish(&mut buf).unwrap();
            encoded.extend_from_slice(&buf[..pf.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }

        let mut decoded = Vec::new();
        let mut i = 0;
        while i < encoded.len() {
            let (pd, status) = dec.decode(&encoded[i..], &mut buf).unwrap();
            decoded.extend_from_slice(&buf[..pd.written]);
            i += pd.consumed;
            match status {
                Status::InputEmpty | Status::StreamEnd => break,
                Status::OutputFull => continue,
            }
        }
        loop {
            let (pdf, status) = dec.finish(&mut buf).unwrap();
            decoded.extend_from_slice(&buf[..pdf.written]);
            if matches!(status, Status::StreamEnd) {
                break;
            }
        }
        assert_eq!(decoded, input);
    }

    #[test]
    fn lzx_extension_still_points_at_cab() {
        // Even though both codecs share the .lzx extension, the factory's
        // extension table intentionally maps `.lzx` to the MS-CAB codec.
        // This guards against accidental reassignment.
        if cfg!(feature = "lzx") {
            assert_eq!(factory::extension("lzx"), Some("lzx"));
            assert_eq!(factory::extension("amiga_lzx"), None);
        }
    }
}
