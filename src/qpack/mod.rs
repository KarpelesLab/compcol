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
//! # Encoder — static-table + literal only
//!
//! [`QpackEncoder`] emits fully spec-compliant, interoperable field sections
//! that **never insert into the dynamic table**: the prefix is always Required
//! Insert Count = 0, Base = 0, and fields are coded with static-table indexed /
//! name-reference representations or literal names. This needs no encoder
//! stream and never blocks a peer decoder. Dynamic-table *encoding* (driving
//! the encoder stream, post-base references, eviction policy) is a deliberate
//! future extension; the decoder here already accepts a peer that does it.
//!
//! ```
//! use compcol::qpack::{QpackEncoder, QpackDecoder};
//! use compcol::hpack::HeaderField;
//!
//! let mut enc = QpackEncoder::new();
//! let block = enc.encode_field_section(&[
//!     HeaderField::new(b":path", b"/index.html"),
//!     HeaderField::new(b"custom", b"value"),
//! ]);
//! let mut dec = QpackDecoder::new();
//! let out = dec.decode_field_section(&block).unwrap();
//! assert_eq!(out[0].name, b":path");
//! assert_eq!(out[1].value, b"value");
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
use crate::hpack::huffman;

mod dynamic_table;
mod integer;
mod static_table;

use dynamic_table::DynamicTable;
use integer::{decode_int, encode_int};

/// QPACK's default maximum dynamic-table capacity used by [`QpackDecoder::new`]
/// when no explicit bound is given. A peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`
/// would normally set this; 4096 mirrors the HPACK default and is a safe
/// general-purpose ceiling.
pub const DEFAULT_MAX_TABLE_CAPACITY: usize = 4096;

// ─── encoder ───────────────────────────────────────────────────────────────

/// QPACK encoder (static-table + literal only).
///
/// Encodes each field section against the static table, emitting a Required
/// Insert Count = 0 / Base = 0 prefix and never inserting into the dynamic
/// table. This is stateless across calls and fully interoperable. See the
/// [module docs](crate::qpack) for why dynamic-table encoding is out of scope.
#[derive(Debug)]
pub struct QpackEncoder {
    use_huffman: bool,
}

impl Default for QpackEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl QpackEncoder {
    /// New encoder with Huffman string coding enabled.
    pub fn new() -> Self {
        QpackEncoder { use_huffman: true }
    }

    /// Enable/disable Huffman coding of string literals (default on). When on,
    /// the shorter of Huffman/raw is chosen per string (§4.1.2).
    pub fn set_huffman(&mut self, on: bool) {
        self.use_huffman = on;
    }

    /// Encode one field section. The returned block begins with the §4.5.1
    /// prefix (Required Insert Count = 0, Base = 0 — encoded as two `0x00`
    /// bytes) followed by one representation per field.
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
}

impl Default for QpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl QpackDecoder {
    /// New decoder allowing a dynamic table up to
    /// [`DEFAULT_MAX_TABLE_CAPACITY`] bytes.
    pub fn new() -> Self {
        Self::with_max_table_capacity(DEFAULT_MAX_TABLE_CAPACITY)
    }

    /// New decoder whose dynamic-table capacity ceiling is `max` bytes (the
    /// value it would advertise as `SETTINGS_QPACK_MAX_TABLE_CAPACITY`). The
    /// table starts empty at capacity 0 until the encoder stream raises it.
    pub fn with_max_table_capacity(max: usize) -> Self {
        QpackDecoder {
            table: DynamicTable::new(),
            max_capacity: max,
        }
    }

    /// Process encoder-stream instructions (§4.3), mutating the dynamic table:
    /// Set Dynamic Table Capacity, Insert with Name Reference, Insert with
    /// Literal Name, and Duplicate. Returns [`Error::Corrupt`] on a malformed
    /// instruction, a bad table reference, an over-limit capacity, or an insert
    /// that cannot fit; [`Error::UnexpectedEnd`] on truncation.
    pub fn feed_encoder_stream(&mut self, data: &[u8]) -> Result<(), Error> {
        let mut pos = 0;
        while pos < data.len() {
            let b = data[pos];
            if b & 0b1000_0000 != 0 {
                // §4.3.2 Insert with Name Reference: 1 T name-index(6+).
                let t_static = b & 0b0100_0000 != 0;
                let (name_idx, np) = decode_int(data, pos, 6)?;
                pos = np;
                let (value, np) = read_string(data, pos, 7)?;
                pos = np;
                let name = self.resolve_insert_name(name_idx, t_static)?;
                self.do_insert(&name, &value)?;
            } else if b & 0b0100_0000 != 0 {
                // §4.3.3 Insert with Literal Name: 0 1 H name-len(5+).
                let (name, np) = read_string(data, pos, 5)?;
                pos = np;
                let (value, np) = read_string(data, pos, 7)?;
                pos = np;
                self.do_insert(&name, &value)?;
            } else if b & 0b0010_0000 != 0 {
                // §4.3.1 Set Dynamic Table Capacity: 0 0 1 capacity(5+).
                let (cap, np) = decode_int(data, pos, 5)?;
                pos = np;
                if !self.table.set_capacity(cap, self.max_capacity) {
                    return Err(Error::Corrupt);
                }
            } else {
                // §4.3.4 Duplicate: 0 0 0 index(5+) (relative index).
                let (rel, np) = decode_int(data, pos, 5)?;
                pos = np;
                let abs = self
                    .table
                    .relative_to_absolute_encoder(rel)
                    .ok_or(Error::Corrupt)?;
                let (n, v) = self.table.get_absolute(abs).ok_or(Error::Corrupt)?;
                let (n, v) = (n.to_vec(), v.to_vec());
                self.do_insert(&n, &v)?;
            }
        }
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
    /// [`Error::UnexpectedEnd`] on truncation.
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

        let mut fields = Vec::new();
        while pos < block.len() {
            let b = block[pos];
            if b & 0b1000_0000 != 0 {
                // §4.5.2 Indexed Field Line: 1 T index(6+).
                let t_static = b & 0b0100_0000 != 0;
                let (idx, np) = decode_int(block, pos, 6)?;
                pos = np;
                let (n, v) = self.lookup_indexed(idx, t_static, base, req_insert_count)?;
                fields.push(HeaderField::new(n.as_slice(), v.as_slice()));
            } else if b & 0b0100_0000 != 0 {
                // §4.5.4 Literal Field Line with Name Reference: 0 1 N T idx(4+).
                let sensitive = b & 0b0010_0000 != 0;
                let t_static = b & 0b0001_0000 != 0;
                let (idx, np) = decode_int(block, pos, 4)?;
                pos = np;
                let name = self.lookup_name_ref(idx, t_static, base, req_insert_count)?;
                let (value, np) = read_string(block, pos, 7)?;
                pos = np;
                fields.push(HeaderField {
                    name,
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
                fields.push(HeaderField::new(n.as_slice(), v.as_slice()));
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
                fields.push(HeaderField {
                    name: n,
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
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if t_static {
            let (n, v) = static_table::get(idx).ok_or(Error::Corrupt)?;
            Ok((n.to_vec(), v.to_vec()))
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
    ) -> Result<Vec<u8>, Error> {
        if t_static {
            let (n, _) = static_table::get(idx).ok_or(Error::Corrupt)?;
            Ok(n.to_vec())
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
    ) -> Result<(Vec<u8>, Vec<u8>), Error> {
        if abs >= req_insert_count {
            return Err(Error::Corrupt);
        }
        let (n, v) = self.table.get_absolute(abs).ok_or(Error::Corrupt)?;
        Ok((n.to_vec(), v.to_vec()))
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

#[cfg(test)]
mod tests;
