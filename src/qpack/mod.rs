//! HTTP/3 QPACK header compression — [RFC 9204].
//!
//! QPACK is HTTP/3's header-compression format. Like [HPACK](crate::hpack) it
//! compresses an ordered list of `(name, value)` header fields against a
//! static table (99 common fields, RFC 9204 Appendix A) and a per-connection
//! dynamic table — but it is designed for QUIC's out-of-order streams, so the
//! dynamic table is mutated by a **separate, ordered encoder stream** while
//! field sections (the per-request header blocks) reference it through a
//! prefix that names how many insertions the decoder must have seen first.
//!
//! This module reuses HPACK's machinery where the specs agree: the string
//! Huffman code is identical, so [`HeaderField`] and the
//! [`crate::hpack::huffman`] primitive come straight from
//! [`crate::hpack`]. The prefixed-integer and table primitives are
//! QPACK-specific (different index spaces) and live here.
//!
//! # Decoder — full
//!
//! [`QpackDecoder`] implements the complete decode path: the static table, the
//! dynamic table built from the encoder stream
//! ([`feed_encoder_stream`](QpackDecoder::feed_encoder_stream): Set Dynamic
//! Table Capacity, Insert with Name Reference, Insert with Literal Name,
//! Duplicate), and every field-line representation
//! ([`decode_field_section`](QpackDecoder::decode_field_section): indexed
//! static/dynamic/post-base, literal with static/dynamic/post-base name
//! reference, literal with literal name).
//!
//! Because this is a synchronous API it cannot *block* on a field section that
//! references dynamic entries not yet inserted: if a section's Required Insert
//! Count exceeds the decoder's current Insert Count, it returns
//! [`Error::Corrupt`] rather than waiting. Feed the encoder stream first.
//!
//! The encoder stream can be fed in whatever pieces it comes off the QUIC
//! stream in: the decoder keeps the bytes of an instruction that is not
//! complete yet and applies each instruction exactly once.
//!
//! # Encoder — static-only and dynamic-table modes
//!
//! [`QpackEncoder`] has two modes:
//!
//! * **Static-only** ([`QpackEncoder::new`], used via
//!   [`encode_field_section`](QpackEncoder::encode_field_section)): emits a
//!   single field section that **never inserts into the dynamic table** — the
//!   prefix is always Required Insert Count = 0, Base = 0, and fields use
//!   static-table indexed / name-reference representations or literal names.
//!   No encoder stream, never blocks a peer decoder.
//!
//! * **Dynamic** ([`QpackEncoder::with_dynamic_table`], used via
//!   [`encode`](QpackEncoder::encode)): maintains a mirror of the peer
//!   decoder's dynamic table and returns an [`Encoded`] pair — the encoder-stream
//!   bytes that build the table (Set Dynamic Table Capacity, Insert with
//!   Name Reference against static or dynamic names, Insert with Literal Name)
//!   and the field section that references it (indexed / name-reference
//!   dynamic representations with a non-zero Required Insert Count). Entries
//!   referenced by a field section are never evicted by inserts in the same
//!   batch, and sensitive fields are kept out of the table (coded never-indexed).
//!
//! Because this is a synchronous API with no decoder-feedback channel, the
//! caller must deliver each [`Encoded::encoder_stream`] chunk to the peer's
//! [`QpackDecoder::feed_encoder_stream`] **before** the matching
//! [`Encoded::field_section`], in order. The encoder's `MaxEntries` (and hence
//! the Required Insert Count encoding) is derived from the capacity passed to
//! [`with_dynamic_table`](QpackEncoder::with_dynamic_table), which must equal
//! the decoder's `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (see
//! [`QpackDecoder::with_limits`]).
//!
//! ```
//! use compcol::qpack::{QpackEncoder, QpackDecoder};
//! use compcol::hpack::HeaderField;
//!
//! // Static-only single-shot.
//! let mut enc = QpackEncoder::new();
//! let block = enc.encode_field_section(&[
//!     HeaderField::new(b":path", b"/index.html"),
//!     HeaderField::new(b"custom", b"value"),
//! ]);
//! let mut dec = QpackDecoder::with_limits(4096, 64 * 1024);
//! let out = dec.decode_field_section(&block).unwrap();
//! assert_eq!(out[0].name, b":path");
//! assert_eq!(out[1].value, b"value");
//!
//! // Dynamic: build the table on the encoder stream, reference it from the
//! // field section. Feed the encoder stream first, then decode.
//! let mut enc = QpackEncoder::with_dynamic_table(4096);
//! let mut dec = QpackDecoder::with_limits(4096, 64 * 1024);
//! let fields = [HeaderField::new(b"custom-key", b"custom-value")];
//! let first = enc.encode(&fields);
//! dec.feed_encoder_stream(&first.encoder_stream).unwrap();
//! assert_eq!(dec.decode_field_section(&first.field_section).unwrap(), fields);
//! // A later section reuses the entry with no new insertions.
//! let again = enc.encode(&fields);
//! assert!(again.encoder_stream.is_empty());
//! dec.feed_encoder_stream(&again.encoder_stream).unwrap();
//! assert_eq!(dec.decode_field_section(&again.field_section).unwrap(), fields);
//! ```
//!
//! Clean-room from RFC 9204 (the static table is transcribed from Appendix A;
//! the string Huffman table is HPACK's, shared per the spec).
//!
//! [RFC 9204]: https://www.rfc-editor.org/rfc/rfc9204

#![cfg_attr(docsrs, doc(cfg(feature = "qpack")))]

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;
use crate::hpack::HeaderField;
use crate::hpack::{charge_field, huffman};

mod dynamic_table;
mod integer;
mod static_table;

use dynamic_table::DynamicTable;
use integer::{decode_int, encode_int};

/// QPACK's default maximum dynamic-table capacity used by
/// [`QpackDecoder::default`] when no explicit bound is given. A peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`
/// would normally set this; 4096 mirrors the HPACK default and is a safe
/// general-purpose ceiling.
pub const DEFAULT_MAX_TABLE_CAPACITY: usize = 4096;

/// Default cap on one decoded field section, in RFC 9204 §3.2.1 field-size
/// units (name + value + 32 bytes per field). Applied by the constructors that
/// don't take a cap ([`QpackDecoder::default`] and the deprecated
/// [`QpackDecoder::new`] / [`QpackDecoder::with_max_table_capacity`]). See
/// [`QpackDecoder::with_limits`] for why the decoder enforces this itself.
pub const DEFAULT_MAX_FIELD_SECTION_SIZE: usize = 64 * 1024;

// ─── encoder ───────────────────────────────────────────────────────────────

/// Output of [`QpackEncoder::encode`]: the encoder-stream bytes that build the
/// peer decoder's dynamic table and the field section that references it.
///
/// Deliver `encoder_stream` to the peer's
/// [`QpackDecoder::feed_encoder_stream`] **before** handing it `field_section`
/// (this synchronous API cannot wait on a blocked reference). `encoder_stream`
/// is empty when a section needs no new insertions.
#[derive(Debug, Clone)]
pub struct Encoded {
    /// Encoder-stream instructions (§4.3) that mutate the dynamic table.
    pub encoder_stream: Vec<u8>,
    /// The field section (§4.5) referencing the static and dynamic tables.
    pub field_section: Vec<u8>,
}

/// QPACK encoder.
///
/// Constructed [statically](Self::new) (no dynamic table; use
/// [`encode_field_section`](Self::encode_field_section)) or with a
/// [dynamic table](Self::with_dynamic_table) (use [`encode`](Self::encode)).
/// See the [module docs](crate::qpack) for the two modes and the
/// feed-encoder-stream-first contract.
#[derive(Debug)]
pub struct QpackEncoder {
    use_huffman: bool,
    /// Mirror of the peer decoder's dynamic table. Capacity is 0 in
    /// static-only mode, leaving every code path below dynamic-free.
    table: DynamicTable,
    /// Working dynamic-table capacity, also the value announced via Set Dynamic
    /// Table Capacity. 0 means static-only.
    target_capacity: usize,
    /// `MaxEntries` (capacity / 32) used to encode the Required Insert Count
    /// (§4.5.1.1); must match the decoder's `max_capacity / 32`.
    max_entries: usize,
    /// Whether the Set Dynamic Table Capacity instruction has been emitted on
    /// the encoder stream yet (sent lazily before the first insert).
    capacity_announced: bool,
}

/// One field's chosen representation, decided in a first pass (which also emits
/// the encoder-stream inserts and computes the Required Insert Count) before
/// the prefix and field bytes are emitted in a second pass.
enum FieldRep<'a> {
    StaticIdx(usize),
    DynIdx(usize),
    StaticName {
        idx: usize,
        value: &'a [u8],
        sensitive: bool,
    },
    DynName {
        abs: usize,
        value: &'a [u8],
        sensitive: bool,
    },
    Literal {
        name: &'a [u8],
        value: &'a [u8],
        sensitive: bool,
    },
}

impl Default for QpackEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl QpackEncoder {
    /// New static-only encoder with Huffman string coding enabled. It never
    /// inserts into the dynamic table; use
    /// [`encode_field_section`](Self::encode_field_section).
    pub fn new() -> Self {
        QpackEncoder {
            use_huffman: true,
            table: DynamicTable::new(),
            target_capacity: 0,
            max_entries: 0,
            capacity_announced: false,
        }
    }

    /// New encoder that uses a dynamic table of up to `max_table_capacity`
    /// bytes, driven through [`encode`](Self::encode).
    ///
    /// `max_table_capacity` is both the capacity this encoder will request (via
    /// Set Dynamic Table Capacity) and the basis for its `MaxEntries`, so it
    /// **must equal** the peer decoder's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`
    /// (the first value passed to [`QpackDecoder::with_limits`], or
    /// [`DEFAULT_MAX_TABLE_CAPACITY`] for [`QpackDecoder::default`]). Passing 0
    /// yields a static-only encoder.
    pub fn with_dynamic_table(max_table_capacity: usize) -> Self {
        let mut table = DynamicTable::new();
        table.set_capacity(max_table_capacity, max_table_capacity);
        QpackEncoder {
            use_huffman: true,
            table,
            target_capacity: max_table_capacity,
            max_entries: max_table_capacity / 32,
            capacity_announced: false,
        }
    }

    /// Enable/disable Huffman coding of string literals (default on). When on,
    /// the shorter of Huffman/raw is chosen per string (§4.1.2).
    pub fn set_huffman(&mut self, on: bool) {
        self.use_huffman = on;
    }

    /// Entries inserted into the encoder's mirror table so far (for
    /// tests/inspection).
    #[cfg(test)]
    pub(crate) fn insert_count(&self) -> usize {
        self.table.insert_count()
    }

    /// Encode one field section against the static table only, returning a
    /// self-contained block. The block begins with the §4.5.1 prefix (Required
    /// Insert Count = 0, Base = 0 — two `0x00` bytes) followed by one
    /// representation per field. This ignores any dynamic table and emits no
    /// encoder stream; for dynamic-table encoding use [`encode`](Self::encode).
    pub fn encode_field_section(&mut self, fields: &[HeaderField]) -> Vec<u8> {
        let mut out = Vec::new();
        // §4.5.1 prefix. With no dynamic-table references, Required Insert
        // Count encodes as 0 (8-bit prefix) and Delta Base as 0 with Sign 0.
        out.push(0x00); // Required Insert Count = 0
        out.push(0x00); // S = 0, Delta Base = 0  → Base = 0
        for f in fields {
            self.encode_field(&mut out, f);
        }
        out
    }

    /// Encode one field section using the dynamic table, returning the
    /// [`Encoded`] encoder-stream / field-section pair.
    ///
    /// For each field the encoder prefers, in order: a static full match
    /// (indexed, no table change); an existing dynamic full match (indexed
    /// dynamic); inserting a new entry (emitting an encoder-stream instruction
    /// and referencing it); or a field-section literal with a static/dynamic
    /// name reference or a literal name. Sensitive fields are never inserted and
    /// are coded with the never-indexed bit set. An insert is skipped when it
    /// would not fit, or when it would evict an entry already referenced by this
    /// field section. On a static-only encoder ([`new`](Self::new)) this returns
    /// an empty `encoder_stream` and a field section identical to
    /// [`encode_field_section`](Self::encode_field_section).
    pub fn encode<'a>(&mut self, fields: &'a [HeaderField]) -> Encoded {
        let mut estream = Vec::new();
        let mut reps: Vec<FieldRep<'a>> = Vec::with_capacity(fields.len());
        // Required Insert Count = (highest referenced absolute index) + 1.
        let mut required_insert_count = 0usize;
        // Absolute indices referenced by this field section; none of them may be
        // evicted by an insert in the same batch (the section is decoded as a
        // unit, after the whole encoder-stream chunk is applied).
        let mut referenced: Vec<usize> = Vec::new();

        for f in fields {
            let static_match = static_table::find(&f.name, &f.value);
            // The mirror table changes as we insert, so this is recomputed per
            // field. Sensitive fields skip the dynamic table entirely.
            let dyn_match = if f.sensitive {
                None
            } else {
                self.table.find(&f.name, &f.value)
            };

            // 1. Static full match (non-sensitive) → Indexed Field Line.
            //    A sensitive full match falls through to a never-indexed literal.
            if let Some((idx, true)) = static_match.filter(|_| !f.sensitive) {
                reps.push(FieldRep::StaticIdx(idx));
                continue;
            }

            // 2. Existing dynamic full match → Indexed Field Line (dynamic).
            if let Some((abs, true)) = dyn_match {
                reps.push(FieldRep::DynIdx(abs));
                required_insert_count = required_insert_count.max(abs + 1);
                referenced.push(abs);
                continue;
            }

            // 3. Insert a new entry, if it fits and evicts nothing we reference.
            if !f.sensitive && self.target_capacity > 0 {
                let size = DynamicTable::entry_size(&f.name, &f.value);
                if size <= self.target_capacity {
                    let floor = self.table.evict_floor(size);
                    if referenced.iter().all(|&a| a >= floor) {
                        // The decoder resolves an insert's name reference before
                        // applying eviction, so a name source may itself be
                        // evicted by this insert — only `referenced` must survive.
                        if !self.capacity_announced {
                            // §4.3.1 Set Dynamic Table Capacity: 0 0 1 cap(5+).
                            encode_int(&mut estream, self.target_capacity, 5, 0b0010_0000);
                            self.capacity_announced = true;
                        }
                        self.emit_insert(
                            &mut estream,
                            &f.name,
                            &f.value,
                            static_match.map(|(idx, _)| idx),
                            dyn_match.map(|(abs, _)| abs),
                        );
                        let abs = self
                            .table
                            .insert(&f.name, &f.value)
                            .expect("size <= capacity checked");
                        reps.push(FieldRep::DynIdx(abs));
                        required_insert_count = required_insert_count.max(abs + 1);
                        referenced.push(abs);
                        continue;
                    }
                }
            }

            // 4. Field-section literal: static name ref, dynamic name ref, or
            //    literal name.
            if let Some((idx, _)) = static_match {
                reps.push(FieldRep::StaticName {
                    idx,
                    value: &f.value,
                    sensitive: f.sensitive,
                });
            } else if let Some((abs, _)) = dyn_match {
                required_insert_count = required_insert_count.max(abs + 1);
                referenced.push(abs);
                reps.push(FieldRep::DynName {
                    abs,
                    value: &f.value,
                    sensitive: false,
                });
            } else {
                reps.push(FieldRep::Literal {
                    name: &f.name,
                    value: &f.value,
                    sensitive: f.sensitive,
                });
            }
        }

        let field_section = self.emit_field_section(required_insert_count, &reps);
        Encoded {
            encoder_stream: estream,
            field_section,
        }
    }

    /// Emit an Insert instruction (§4.3.2 / §4.3.3) for `value`, choosing the
    /// name representation: a static name reference if available, else a dynamic
    /// (relative) name reference, else a literal name. The name index for the
    /// dynamic case is relative to the most recent insertion (§3.2.5).
    fn emit_insert(
        &self,
        est: &mut Vec<u8>,
        name: &[u8],
        value: &[u8],
        static_name: Option<usize>,
        dyn_name_abs: Option<usize>,
    ) {
        if let Some(idx) = static_name {
            // §4.3.2 Insert with Name Reference, T = 1 (static): 1 1 idx(6+).
            encode_int(est, idx, 6, 0b1100_0000);
            self.emit_string(est, value, 7, 0);
        } else if let Some(abs) = dyn_name_abs {
            // §4.3.2 Insert with Name Reference, T = 0 (dynamic): 1 0 rel(6+).
            // rel = InsertCount - 1 - abs (relative to the newest entry).
            let rel = self.table.insert_count() - 1 - abs;
            encode_int(est, rel, 6, 0b1000_0000);
            self.emit_string(est, value, 7, 0);
        } else {
            // §4.3.3 Insert with Literal Name: 0 1 H name-len(5+) name value.
            self.emit_string(est, name, 5, 0b0100_0000);
            self.emit_string(est, value, 7, 0);
        }
    }

    /// Second pass: emit the §4.5.1 prefix (Required Insert Count + Base) and
    /// then one representation per field. Base is fixed at Required Insert Count,
    /// so every dynamic reference is a pre-base relative index and no post-base
    /// forms are needed.
    fn emit_field_section(&self, required_insert_count: usize, reps: &[FieldRep<'_>]) -> Vec<u8> {
        let base = required_insert_count;
        let mut out = Vec::new();
        self.emit_prefix(&mut out, required_insert_count, base);
        for rep in reps {
            match *rep {
                FieldRep::StaticIdx(idx) => {
                    // §4.5.2 Indexed Field Line, static: 1 T(=1) index(6+).
                    encode_int(&mut out, idx, 6, 0b1100_0000);
                }
                FieldRep::DynIdx(abs) => {
                    // §4.5.2 Indexed Field Line, dynamic: 1 T(=0) index(6+).
                    let rel = base - 1 - abs;
                    encode_int(&mut out, rel, 6, 0b1000_0000);
                }
                FieldRep::StaticName {
                    idx,
                    value,
                    sensitive,
                } => {
                    // §4.5.4 Literal w/ Name Reference, static: 0 1 N T(=1) idx(4+).
                    let n_bit = if sensitive { 0b0010_0000 } else { 0 };
                    encode_int(&mut out, idx, 4, 0b0101_0000 | n_bit);
                    self.emit_string(&mut out, value, 7, 0);
                }
                FieldRep::DynName {
                    abs,
                    value,
                    sensitive,
                } => {
                    // §4.5.4 Literal w/ Name Reference, dynamic: 0 1 N T(=0) idx(4+).
                    let rel = base - 1 - abs;
                    let n_bit = if sensitive { 0b0010_0000 } else { 0 };
                    encode_int(&mut out, rel, 4, 0b0100_0000 | n_bit);
                    self.emit_string(&mut out, value, 7, 0);
                }
                FieldRep::Literal {
                    name,
                    value,
                    sensitive,
                } => {
                    // §4.5.6 Literal Field Line with Literal Name: 0 0 1 N H len(3+).
                    let n_bit = if sensitive { 0b0001_0000 } else { 0 };
                    self.emit_string(&mut out, name, 3, 0b0010_0000 | n_bit);
                    self.emit_string(&mut out, value, 7, 0);
                }
            }
        }
        out
    }

    /// Emit the §4.5.1 prefix: Required Insert Count (§4.5.1.1) then Base as a
    /// sign bit + 7-bit Delta Base relative to Required Insert Count.
    fn emit_prefix(&self, out: &mut Vec<u8>, required_insert_count: usize, base: usize) {
        if required_insert_count == 0 {
            out.push(0x00);
        } else {
            // EncInsertCount = (ReqInsertCount mod (2*MaxEntries)) + 1.
            let enc = (required_insert_count % (2 * self.max_entries)) + 1;
            encode_int(out, enc, 8, 0);
        }
        if base >= required_insert_count {
            // Sign = 0, Delta Base = Base - ReqInsertCount.
            encode_int(out, base - required_insert_count, 7, 0);
        } else {
            // Sign = 1, Delta Base = ReqInsertCount - Base - 1.
            encode_int(out, required_insert_count - base - 1, 7, 0b1000_0000);
        }
    }

    fn encode_field(&self, out: &mut Vec<u8>, f: &HeaderField) {
        match static_table::find(&f.name, &f.value) {
            Some((idx, true)) if !f.sensitive => {
                // §4.5.2 Indexed Field Line, static table: 1 T(=1) index(6+).
                encode_int(out, idx, 6, 0b1100_0000);
            }
            Some((idx, _)) => {
                // §4.5.4 Literal Field Line with Name Reference, static table.
                // Pattern 0 1 N T, 4-bit name index. T=1 (static).
                let n_bit = if f.sensitive { 0b0010_0000 } else { 0 };
                encode_int(out, idx, 4, 0b0101_0000 | n_bit);
                self.emit_string(out, &f.value, 7, 0);
            }
            None => {
                // §4.5.6 Literal Field Line with Literal Name. Pattern
                // 0 0 1 N H, 3-bit name length. emit_string handles the H bit.
                let n_bit = if f.sensitive { 0b0001_0000 } else { 0 };
                self.emit_string(out, &f.name, 3, 0b0010_0000 | n_bit);
                self.emit_string(out, &f.value, 7, 0);
            }
        }
    }

    /// Emit a string literal (§4.1.2) with an `n`-bit length prefix. `pattern`
    /// holds the fixed high bits already positioned; the Huffman (`H`) flag is
    /// the bit at value `1 << n` and is OR-ed in when Huffman is chosen.
    fn emit_string(&self, out: &mut Vec<u8>, s: &[u8], n: u32, pattern: u8) {
        let h_flag = 1u8 << n;
        if self.use_huffman && huffman::encoded_len(s) < s.len() {
            let coded = huffman::encode(s);
            encode_int(out, coded.len(), n, pattern | h_flag);
            out.extend_from_slice(&coded);
        } else {
            encode_int(out, s.len(), n, pattern);
            out.extend_from_slice(s);
        }
    }
}

// ─── decoder ───────────────────────────────────────────────────────────────

/// QPACK decoder (full: static + dynamic tables + all field representations).
///
/// Feed the encoder stream with
/// [`feed_encoder_stream`](Self::feed_encoder_stream) (which builds the dynamic
/// table) before decoding the field sections that reference it with
/// [`decode_field_section`](Self::decode_field_section). The dynamic table and
/// Insert Count persist across calls for the lifetime of the connection.
#[derive(Debug)]
pub struct QpackDecoder {
    table: DynamicTable,
    /// Connection limit on dynamic-table capacity
    /// (`SETTINGS_QPACK_MAX_TABLE_CAPACITY`, §3.2.3). A Set Dynamic Table
    /// Capacity instruction may not exceed this.
    max_capacity: usize,
    /// Cap on one decoded field section, in §3.2.1 field-size units.
    max_field_section_size: usize,
    /// Leading bytes of an encoder-stream instruction whose remainder has not
    /// arrived yet. Never holds a complete instruction, and is bounded by
    /// the table capacity (see `scan_instruction`).
    encoder_stream_tail: Vec<u8>,
    /// The error that ended the encoder stream; every later
    /// [`feed_encoder_stream`](Self::feed_encoder_stream) call returns it.
    encoder_stream_error: Option<Error>,
}

/// [`DEFAULT_MAX_TABLE_CAPACITY`] with the [`DEFAULT_MAX_FIELD_SECTION_SIZE`]
/// cap.
impl Default for QpackDecoder {
    fn default() -> Self {
        Self::with_limits(DEFAULT_MAX_TABLE_CAPACITY, DEFAULT_MAX_FIELD_SECTION_SIZE)
    }
}

impl QpackDecoder {
    /// New decoder allowing a dynamic table up to
    /// [`DEFAULT_MAX_TABLE_CAPACITY`] bytes, with the
    /// [`DEFAULT_MAX_FIELD_SECTION_SIZE`] cap.
    #[deprecated(
        since = "0.7.4",
        note = "choose a decoded-size cap explicitly: use `QpackDecoder::with_limits`"
    )]
    pub fn new() -> Self {
        Self::default()
    }

    /// New decoder whose dynamic-table capacity ceiling is `max` bytes, with
    /// the [`DEFAULT_MAX_FIELD_SECTION_SIZE`] cap.
    #[deprecated(
        since = "0.7.4",
        note = "choose a decoded-size cap explicitly: use `QpackDecoder::with_limits`"
    )]
    pub fn with_max_table_capacity(max: usize) -> Self {
        Self::with_limits(max, DEFAULT_MAX_FIELD_SECTION_SIZE)
    }

    /// New decoder whose dynamic-table capacity ceiling is
    /// `max_table_capacity` bytes (the value it advertises as
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`), and which rejects any field
    /// section decoding to more than `max_field_section_size` bytes, counted
    /// as in RFC 9204 §3.2.1 (name + value + 32 per field), the same unit as
    /// HTTP/3 `SETTINGS_MAX_FIELD_SECTION_SIZE`. `usize::MAX` disables the
    /// cap. The table starts empty at capacity 0 until the encoder stream
    /// raises it.
    ///
    /// The decoder enforces the cap itself because a one-byte indexed field
    /// line can expand to a whole dynamic-table entry (~4 KiB), so a small
    /// field section can decode to gigabytes before the caller sees the
    /// result. The budget is charged as each field is decoded, and decoding
    /// stops early. It applies per
    /// [`decode_field_section`](Self::decode_field_section) call; a caller
    /// that accepts several HEADERS frames on one stream must sum the sizes
    /// itself.
    pub fn with_limits(max_table_capacity: usize, max_field_section_size: usize) -> Self {
        QpackDecoder {
            table: DynamicTable::new(),
            max_capacity: max_table_capacity,
            max_field_section_size,
            encoder_stream_tail: Vec::new(),
            encoder_stream_error: None,
        }
    }

    /// Change the decoded-size cap set by [`with_limits`](Self::with_limits).
    pub fn set_max_field_section_size(&mut self, max: usize) {
        self.max_field_section_size = max;
    }

    /// Process the next bytes of the encoder stream (§4.3), mutating the
    /// dynamic table: Set Dynamic Table Capacity, Insert with Name Reference,
    /// Insert with Literal Name, and Duplicate.
    ///
    /// The encoder stream is a QUIC byte stream, so `data` may start and end
    /// anywhere, including in the middle of an instruction: call this with
    /// each chunk as it arrives, in order, and never feed a byte twice. Every
    /// instruction is applied exactly once, however the bytes are split. When
    /// a chunk ends inside an instruction, the unparsed bytes are kept in the
    /// decoder and the call returns `Ok(())`; the instruction is applied once
    /// the rest of it has been fed.
    /// [`encoder_stream_pending`](Self::encoder_stream_pending) tells how
    /// many such bytes are held. This method therefore never returns
    /// [`Error::UnexpectedEnd`]: a truncated instruction is only an error if
    /// the stream has ended, which the caller knows and the decoder does not
    /// (and the encoder stream ending is itself a connection error, RFC 9204
    /// §4.2).
    ///
    /// The bytes held are bounded by the dynamic table's current capacity:
    /// an insert whose strings could not fit in the table is rejected as
    /// soon as their length prefixes have been read, without waiting for (or
    /// buffering) the strings. At most about four times the capacity is
    /// held, since a Huffman-coded string can be that much longer than the
    /// text it decodes to.
    ///
    /// Returns [`Error::Corrupt`] on a malformed instruction, a bad table
    /// reference, an over-limit capacity, or an insert that cannot fit. Such
    /// an error is a connection error (`QPACK_ENCODER_STREAM_ERROR`, RFC 9204
    /// §6) and is final: the instructions that preceded the bad one stay
    /// applied, the bad one and everything after it are dropped, and every
    /// later call returns the same error without reading its input.
    pub fn feed_encoder_stream(&mut self, data: &[u8]) -> Result<(), Error> {
        if let Some(e) = self.encoder_stream_error {
            return Err(e);
        }
        let res = if self.encoder_stream_tail.is_empty() {
            // Nothing held: parse straight from the caller's slice and keep
            // only the incomplete instruction at its end, if any.
            self.apply_encoder_stream(data).map(|used| {
                self.encoder_stream_tail.extend_from_slice(&data[used..]);
            })
        } else {
            let mut buf = core::mem::take(&mut self.encoder_stream_tail);
            buf.extend_from_slice(data);
            self.apply_encoder_stream(&buf).map(|used| {
                buf.drain(..used);
                self.encoder_stream_tail = buf;
            })
        };
        if let Err(e) = res {
            self.encoder_stream_tail = Vec::new();
            self.encoder_stream_error = Some(e);
        }
        res
    }

    /// Number of encoder-stream bytes received by
    /// [`feed_encoder_stream`](Self::feed_encoder_stream) that are the start
    /// of an instruction whose end has not arrived yet. `0` means the bytes
    /// fed so far end on an instruction boundary. If the encoder stream ends
    /// while this is non-zero, its last instruction was truncated.
    pub fn encoder_stream_pending(&self) -> usize {
        self.encoder_stream_tail.len()
    }

    /// Apply every complete instruction at the front of `data` and return
    /// how many bytes they took. The rest (`data[used..]`) is the start of
    /// one incomplete instruction, or empty.
    fn apply_encoder_stream(&mut self, data: &[u8]) -> Result<usize, Error> {
        let mut pos = 0;
        while pos < data.len() {
            // Find the instruction's end first, reading only its integers:
            // an incomplete instruction then costs O(1) per call, however
            // many times it is retried as its bytes trickle in.
            let Some(len) = self.scan_instruction(&data[pos..])? else {
                break;
            };
            self.apply_instruction(&data[pos..pos + len])?;
            pos += len;
        }
        Ok(pos)
    }

    /// Length of the instruction starting at `data[0]`, or `None` if `data`
    /// ends before the instruction does. Decodes no string and changes
    /// nothing.
    ///
    /// An insert that cannot fit in the table at its current capacity (which
    /// is exact here: every earlier instruction has been applied) is
    /// [`Error::Corrupt`] from its string length prefixes alone, so the
    /// caller only ever buffers an instruction that could still be valid.
    fn scan_instruction(&self, data: &[u8]) -> Result<Option<usize>, Error> {
        let b = data[0];
        let scanned = if b & 0b1100_0000 != 0 {
            // Bytes left for the new entry's name and value (§3.2.1).
            let mut room = self
                .table
                .capacity()
                .checked_sub(dynamic_table::ENTRY_OVERHEAD)
                .ok_or(Error::Corrupt)?;
            if b & 0b1000_0000 != 0 {
                // §4.3.2 Insert with Name Reference: 1 T name-index(6+),
                // then the value.
                decode_int(data, 0, 6).and_then(|(_, p)| scan_string(data, p, 7, &mut room))
            } else {
                // §4.3.3 Insert with Literal Name: 0 1 H name-len(5+), then
                // the value.
                scan_string(data, 0, 5, &mut room).and_then(|p| scan_string(data, p, 7, &mut room))
            }
        } else {
            // §4.3.1 Set Dynamic Table Capacity and §4.3.4 Duplicate are one
            // 5-bit-prefix integer.
            decode_int(data, 0, 5).map(|(_, p)| p)
        };
        match scanned {
            Ok(end) => Ok(Some(end)),
            // The only way these report truncation is by running off `data`.
            Err(Error::UnexpectedEnd) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Apply the one complete instruction in `ins`, as delimited by
    /// [`scan_instruction`](Self::scan_instruction).
    fn apply_instruction(&mut self, ins: &[u8]) -> Result<(), Error> {
        let b = ins[0];
        let end = if b & 0b1000_0000 != 0 {
            // §4.3.2 Insert with Name Reference: 1 T name-index(6+).
            let t_static = b & 0b0100_0000 != 0;
            let (name_idx, pos) = decode_int(ins, 0, 6)?;
            let (value, pos) = read_string(ins, pos, 7)?;
            let name = self.resolve_insert_name(name_idx, t_static)?;
            self.do_insert(&name, &value)?;
            pos
        } else if b & 0b0100_0000 != 0 {
            // §4.3.3 Insert with Literal Name: 0 1 H name-len(5+).
            let (name, pos) = read_string(ins, 0, 5)?;
            let (value, pos) = read_string(ins, pos, 7)?;
            self.do_insert(&name, &value)?;
            pos
        } else if b & 0b0010_0000 != 0 {
            // §4.3.1 Set Dynamic Table Capacity: 0 0 1 capacity(5+).
            let (cap, pos) = decode_int(ins, 0, 5)?;
            if !self.table.set_capacity(cap, self.max_capacity) {
                return Err(Error::Corrupt);
            }
            pos
        } else {
            // §4.3.4 Duplicate: 0 0 0 index(5+) (relative index).
            let (rel, pos) = decode_int(ins, 0, 5)?;
            let abs = self
                .table
                .relative_to_absolute_encoder(rel)
                .ok_or(Error::Corrupt)?;
            let (n, v) = self.table.get_absolute(abs).ok_or(Error::Corrupt)?;
            let (n, v) = (n.to_vec(), v.to_vec());
            self.do_insert(&n, &v)?;
            pos
        };
        debug_assert_eq!(end, ins.len());
        Ok(())
    }

    /// Resolve the name for an Insert with Name Reference (§4.3.2): static index
    /// or dynamic relative index (relative to the most recent insertion).
    fn resolve_insert_name(&self, idx: usize, t_static: bool) -> Result<Vec<u8>, Error> {
        if t_static {
            let (n, _) = static_table::get(idx).ok_or(Error::Corrupt)?;
            Ok(n.to_vec())
        } else {
            let abs = self
                .table
                .relative_to_absolute_encoder(idx)
                .ok_or(Error::Corrupt)?;
            let (n, _) = self.table.get_absolute(abs).ok_or(Error::Corrupt)?;
            Ok(n.to_vec())
        }
    }

    fn do_insert(&mut self, name: &[u8], value: &[u8]) -> Result<(), Error> {
        if !self.table.can_insert(name, value) {
            return Err(Error::Corrupt);
        }
        self.table.insert(name, value).ok_or(Error::Corrupt)?;
        Ok(())
    }

    /// Decode one field section (§4.5) into its field list. Returns
    /// [`Error::Corrupt`] on a malformed representation, a bad table reference,
    /// or a Required Insert Count that exceeds what has been inserted so far
    /// (a blocked reference this synchronous API cannot wait on);
    /// [`Error::UnexpectedEnd`] on truncation; [`Error::OutputLimitExceeded`]
    /// if the decoded fields would exceed the
    /// [field section size cap](Self::set_max_field_section_size) (map this to
    /// HTTP 431 or a stream reset).
    pub fn decode_field_section(&mut self, block: &[u8]) -> Result<Vec<HeaderField>, Error> {
        // §4.5.1 prefix.
        let (req_insert_count, mut pos) = self.decode_required_insert_count(block)?;
        let base = self.decode_base(block, &mut pos, req_insert_count)?;

        // A field section may only reference dynamic entries with absolute
        // index < Required Insert Count, and the decoder must have inserted at
        // least that many. We can't block, so reject if it hasn't.
        if req_insert_count > self.table.insert_count() {
            return Err(Error::Corrupt);
        }

        let max = self.max_field_section_size;
        let mut used = 0usize;
        let mut fields = Vec::new();
        while pos < block.len() {
            let b = block[pos];
            if b & 0b1000_0000 != 0 {
                // §4.5.2 Indexed Field Line: 1 T index(6+).
                let t_static = b & 0b0100_0000 != 0;
                let (idx, np) = decode_int(block, pos, 6)?;
                pos = np;
                let (n, v) = self.lookup_indexed(idx, t_static, base, req_insert_count)?;
                // Charge before copying: this is the amplifying case.
                charge_field(&mut used, max, n, v)?;
                fields.push(HeaderField::new(n, v));
            } else if b & 0b0100_0000 != 0 {
                // §4.5.4 Literal Field Line with Name Reference: 0 1 N T idx(4+).
                let sensitive = b & 0b0010_0000 != 0;
                let t_static = b & 0b0001_0000 != 0;
                let (idx, np) = decode_int(block, pos, 4)?;
                pos = np;
                let name = self.lookup_name_ref(idx, t_static, base, req_insert_count)?;
                let (value, np) = read_string(block, pos, 7)?;
                pos = np;
                charge_field(&mut used, max, name, &value)?;
                fields.push(HeaderField {
                    name: name.to_vec(),
                    value,
                    sensitive,
                });
            } else if b & 0b0010_0000 != 0 {
                // §4.5.6 Literal Field Line with Literal Name: 0 0 1 N H len(3+).
                let sensitive = b & 0b0001_0000 != 0;
                let (name, np) = read_string(block, pos, 3)?;
                pos = np;
                let (value, np) = read_string(block, pos, 7)?;
                pos = np;
                charge_field(&mut used, max, &name, &value)?;
                fields.push(HeaderField {
                    name,
                    value,
                    sensitive,
                });
            } else if b & 0b0001_0000 != 0 {
                // §4.5.3 Indexed Field Line with Post-Base Index: 0 0 0 1 idx(4+).
                let (idx, np) = decode_int(block, pos, 4)?;
                pos = np;
                let abs = DynamicTable::post_base_to_absolute(base, idx).ok_or(Error::Corrupt)?;
                let (n, v) = self.lookup_dynamic_abs(abs, req_insert_count)?;
                charge_field(&mut used, max, n, v)?;
                fields.push(HeaderField::new(n, v));
            } else {
                // §4.5.5 Literal Field Line with Post-Base Name Reference:
                // 0 0 0 0 N idx(3+).
                let sensitive = b & 0b0000_1000 != 0;
                let (idx, np) = decode_int(block, pos, 3)?;
                pos = np;
                let abs = DynamicTable::post_base_to_absolute(base, idx).ok_or(Error::Corrupt)?;
                let (n, _) = self.lookup_dynamic_abs(abs, req_insert_count)?;
                let (value, np) = read_string(block, pos, 7)?;
                pos = np;
                charge_field(&mut used, max, n, &value)?;
                fields.push(HeaderField {
                    name: n.to_vec(),
                    value,
                    sensitive,
                });
            }
        }
        Ok(fields)
    }

    /// Decode the Required Insert Count (§4.5.1): an 8-bit-prefix integer
    /// `EncInsertCount` reconstructed against the current Insert Count.
    fn decode_required_insert_count(&self, block: &[u8]) -> Result<(usize, usize), Error> {
        let (enc, pos) = decode_int(block, 0, 8)?;
        if enc == 0 {
            return Ok((0, pos));
        }
        let max_entries = self.max_capacity / 32;
        let full_range = 2 * max_entries;
        if full_range == 0 || enc > full_range {
            return Err(Error::Corrupt);
        }
        let total_inserts = self.table.insert_count();
        let max_value = total_inserts + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut req = max_wrapped + enc - 1;
        if req > max_value {
            if req <= full_range {
                return Err(Error::Corrupt);
            }
            req -= full_range;
        }
        if req == 0 {
            return Err(Error::Corrupt);
        }
        Ok((req, pos))
    }

    /// Decode the Base (§4.5.1): a sign bit + 7-bit-prefix Delta Base.
    fn decode_base(
        &self,
        block: &[u8],
        pos: &mut usize,
        req_insert_count: usize,
    ) -> Result<usize, Error> {
        let sign = *block.get(*pos).ok_or(Error::UnexpectedEnd)? & 0x80 != 0;
        let (delta, np) = decode_int(block, *pos, 7)?;
        *pos = np;
        if sign {
            // Base = ReqInsertCount - DeltaBase - 1; reject negative.
            req_insert_count
                .checked_sub(delta)
                .and_then(|x| x.checked_sub(1))
                .ok_or(Error::Corrupt)
        } else {
            req_insert_count.checked_add(delta).ok_or(Error::Corrupt)
        }
    }

    /// §4.5.2 indexed lookup: static or dynamic (relative to `base`).
    fn lookup_indexed(
        &self,
        idx: usize,
        t_static: bool,
        base: usize,
        req_insert_count: usize,
    ) -> Result<(&[u8], &[u8]), Error> {
        if t_static {
            static_table::get(idx).ok_or(Error::Corrupt)
        } else {
            let abs = DynamicTable::field_relative_to_absolute(base, idx).ok_or(Error::Corrupt)?;
            self.lookup_dynamic_abs(abs, req_insert_count)
        }
    }

    /// §4.5.4 name-reference lookup: static or dynamic (relative to `base`).
    fn lookup_name_ref(
        &self,
        idx: usize,
        t_static: bool,
        base: usize,
        req_insert_count: usize,
    ) -> Result<&[u8], Error> {
        if t_static {
            let (n, _) = static_table::get(idx).ok_or(Error::Corrupt)?;
            Ok(n)
        } else {
            let abs = DynamicTable::field_relative_to_absolute(base, idx).ok_or(Error::Corrupt)?;
            Ok(self.lookup_dynamic_abs(abs, req_insert_count)?.0)
        }
    }

    /// Look up a dynamic entry by absolute index, enforcing the field section's
    /// Required Insert Count bound (§4.5: a reference may not name an entry with
    /// absolute index >= Required Insert Count).
    fn lookup_dynamic_abs(
        &self,
        abs: usize,
        req_insert_count: usize,
    ) -> Result<(&[u8], &[u8]), Error> {
        if abs >= req_insert_count {
            return Err(Error::Corrupt);
        }
        self.table.get_absolute(abs).ok_or(Error::Corrupt)
    }

    /// Current Insert Count (entries inserted via the encoder stream).
    pub fn insert_count(&self) -> usize {
        self.table.insert_count()
    }

    /// Current dynamic-table byte size (for tests/inspection).
    #[cfg(test)]
    pub(crate) fn table_size(&self) -> usize {
        self.table.size()
    }

    /// Current dynamic-table capacity (for tests/inspection).
    #[cfg(test)]
    pub(crate) fn table_capacity(&self) -> usize {
        self.table.capacity()
    }

    /// Number of live dynamic-table entries (for tests/inspection).
    #[cfg(test)]
    pub(crate) fn table_len(&self) -> usize {
        self.table.len()
    }
}

/// Read a QPACK string literal (§4.1.2) at `pos`: an `n`-bit length prefix
/// whose `1 << n` bit is the Huffman flag, then that many octets,
/// Huffman-decoded if the flag was set.
fn read_string(block: &[u8], pos: usize, n: u32) -> Result<(Vec<u8>, usize), Error> {
    let first = *block.get(pos).ok_or(Error::UnexpectedEnd)?;
    let huff = first & (1u8 << n) != 0;
    let (len, p) = decode_int(block, pos, n)?;
    let end = p.checked_add(len).ok_or(Error::Corrupt)?;
    if end > block.len() {
        return Err(Error::UnexpectedEnd);
    }
    let raw = &block[p..end];
    let data = if huff {
        huffman::decode(raw)?
    } else {
        raw.to_vec()
    };
    Ok((data, end))
}

/// Skip the string literal (§4.1.2) of an encoder-stream insert at `pos`
/// without decoding it, returning the position after it
/// ([`Error::UnexpectedEnd`] if `block` ends first).
///
/// `room` is what is left of the dynamic-table capacity for this entry's name
/// and value. The string's smallest possible decoded length is taken from it
/// as soon as the length prefix is known, and a string that cannot fit is
/// [`Error::Corrupt`] whether or not its octets are present. A raw string
/// decodes to its own length; `len` Huffman octets hold at least
/// `(8 * len - 7) / 30` symbols, rounded up (a code is at most 30 bits long
/// and the padding at most 7).
fn scan_string(block: &[u8], pos: usize, n: u32, room: &mut usize) -> Result<usize, Error> {
    let first = *block.get(pos).ok_or(Error::UnexpectedEnd)?;
    let huff = first & (1u8 << n) != 0;
    let (len, p) = decode_int(block, pos, n)?;
    let min_decoded = if huff {
        let bits = len.checked_mul(8).ok_or(Error::Corrupt)?;
        bits.saturating_sub(7).div_ceil(30)
    } else {
        len
    };
    *room = room.checked_sub(min_decoded).ok_or(Error::Corrupt)?;
    let end = p.checked_add(len).ok_or(Error::Corrupt)?;
    if end > block.len() {
        return Err(Error::UnexpectedEnd);
    }
    Ok(end)
}

#[cfg(test)]
mod tests;
