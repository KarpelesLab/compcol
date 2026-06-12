//! HTTP/2 HPACK header compression — [RFC 7541].
//!
//! HPACK compresses an ordered list of `(name, value)` header fields against
//! a static table (61 common fields) and a per-connection dynamic table.
//! Unlike the byte-stream codecs elsewhere in this crate, an HPACK codec is
//! **stateful across header blocks** (the dynamic table evolves) and operates
//! on header *lists*, not a byte stream — so it has its own API
//! ([`HpackEncoder`] / [`HpackDecoder`]) rather than the
//! [`Encoder`](crate::Encoder) / [`Decoder`](crate::Decoder) traits.
//!
//! The string-literal Huffman coding (§5.2) is also exposed on its own as the
//! [`Http2Huffman`] codec (name `"h2-huffman"`), which *does* use the uniform
//! trait surface.
//!
//! ```
//! use compcol::hpack::{HpackEncoder, HpackDecoder, HeaderField};
//!
//! let mut enc = HpackEncoder::new();
//! let mut dec = HpackDecoder::new();
//! let block = enc.encode(&[
//!     HeaderField::new(b":method", b"GET"),
//!     HeaderField::new(b"custom", b"value"),
//! ]);
//! let out = dec.decode(&block).unwrap();
//! assert_eq!(out[0].name, b":method");
//! assert_eq!(out[1].value, b"value");
//! ```
//!
//! Clean-room from RFC 7541 (the static/Huffman tables are transcribed from
//! its appendices).
//!
//! [RFC 7541]: https://www.rfc-editor.org/rfc/rfc7541

#![cfg_attr(docsrs, doc(cfg(feature = "hpack")))]

extern crate alloc;
use alloc::vec::Vec;

use crate::error::Error;

pub mod huffman;
mod integer;
mod table;

pub use huffman::Http2Huffman;

use integer::{decode_int, encode_int};
use table::DynamicTable;

/// HTTP/2's protocol-default dynamic table size
/// (`SETTINGS_HEADER_TABLE_SIZE`, RFC 7540 §6.5.2).
pub const DEFAULT_TABLE_SIZE: usize = 4096;

/// A decoded/encodable header field.
///
/// `sensitive` marks a field that must never be indexed (RFC 7541 §7.1.3 —
/// e.g. `cookie`/`authorization`); the encoder emits it as "literal never
/// indexed" and never places it in the dynamic table. The decoder sets it on
/// fields received with that representation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HeaderField {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
    pub sensitive: bool,
}

impl HeaderField {
    /// A non-sensitive field.
    pub fn new(name: &[u8], value: &[u8]) -> Self {
        HeaderField {
            name: name.to_vec(),
            value: value.to_vec(),
            sensitive: false,
        }
    }

    /// A sensitive field (never indexed).
    pub fn sensitive(name: &[u8], value: &[u8]) -> Self {
        HeaderField {
            name: name.to_vec(),
            value: value.to_vec(),
            sensitive: true,
        }
    }
}

// ─── encoder ─────────────────────────────────────────────────────────────

/// HPACK encoder. Holds the dynamic table across [`encode`](Self::encode)
/// calls, one call per header block.
#[derive(Debug)]
pub struct HpackEncoder {
    table: DynamicTable,
    use_huffman: bool,
    pending_size_update: Option<usize>,
}

impl Default for HpackEncoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackEncoder {
    /// New encoder with the protocol-default 4096-byte dynamic table and
    /// Huffman string coding enabled.
    pub fn new() -> Self {
        HpackEncoder {
            table: DynamicTable::new(DEFAULT_TABLE_SIZE),
            use_huffman: true,
            pending_size_update: None,
        }
    }

    /// New encoder whose dynamic table is bounded to `max` bytes. A
    /// dynamic-table-size-update (§6.3) is emitted at the start of the next
    /// header block so the peer's decoder tracks the same bound.
    pub fn with_max_table_size(max: usize) -> Self {
        HpackEncoder {
            table: DynamicTable::new(max),
            use_huffman: true,
            pending_size_update: Some(max),
        }
    }

    /// Enable/disable Huffman coding of string literals (default on). When
    /// off, strings are emitted raw; when on, the shorter of Huffman/raw is
    /// chosen per string (§5.2).
    pub fn set_huffman(&mut self, on: bool) {
        self.use_huffman = on;
    }

    /// Encode one header block.
    pub fn encode(&mut self, fields: &[HeaderField]) -> Vec<u8> {
        let mut out = Vec::new();
        if let Some(max) = self.pending_size_update.take() {
            // §6.3: 001 pattern, 5-bit prefix.
            encode_int(&mut out, max, 5, 0x20);
        }
        for f in fields {
            self.encode_field(&mut out, f);
        }
        out
    }

    fn encode_field(&mut self, out: &mut Vec<u8>, f: &HeaderField) {
        if f.sensitive {
            // §6.2.3 literal never indexed (0001 pattern, 4-bit name index).
            let name_idx = self.table.find(&f.name, &f.value).map(|m| m.index);
            // Use only a name match (never index, so a value match is moot).
            let name_idx = match name_idx {
                Some(i) if self.table.get(i).map(|(n, _)| n == f.name).unwrap_or(false) => Some(i),
                _ => None,
            };
            self.emit_literal(out, 0x10, 4, name_idx, &f.name, &f.value);
            return;
        }
        match self.table.find(&f.name, &f.value) {
            Some(m) if m.value_matched => {
                // §6.1 indexed header field (1 pattern, 7-bit index).
                encode_int(out, m.index, 7, 0x80);
            }
            Some(m) => {
                // Name match → §6.2.1 literal with incremental indexing.
                self.emit_literal(out, 0x40, 6, Some(m.index), &f.name, &f.value);
                self.table.insert(&f.name, &f.value);
            }
            None => {
                self.emit_literal(out, 0x40, 6, None, &f.name, &f.value);
                self.table.insert(&f.name, &f.value);
            }
        }
    }

    fn emit_literal(
        &self,
        out: &mut Vec<u8>,
        pattern: u8,
        prefix: u32,
        name_idx: Option<usize>,
        name: &[u8],
        value: &[u8],
    ) {
        match name_idx {
            Some(i) => encode_int(out, i, prefix, pattern),
            None => {
                encode_int(out, 0, prefix, pattern);
                self.emit_string(out, name);
            }
        }
        self.emit_string(out, value);
    }

    fn emit_string(&self, out: &mut Vec<u8>, s: &[u8]) {
        if self.use_huffman && huffman::encoded_len(s) < s.len() {
            let coded = huffman::encode(s);
            encode_int(out, coded.len(), 7, 0x80); // H flag set
            out.extend_from_slice(&coded);
        } else {
            encode_int(out, s.len(), 7, 0x00);
            out.extend_from_slice(s);
        }
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// HPACK decoder. Holds the dynamic table across [`decode`](Self::decode)
/// calls, one call per header block.
#[derive(Debug)]
pub struct HpackDecoder {
    table: DynamicTable,
    /// Connection limit on the dynamic table size: a peer size-update may not
    /// exceed this (§6.3).
    size_limit: usize,
}

impl Default for HpackDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl HpackDecoder {
    /// New decoder with the protocol-default 4096-byte dynamic table.
    pub fn new() -> Self {
        Self::with_max_table_size(DEFAULT_TABLE_SIZE)
    }

    /// New decoder whose dynamic table (and the size-update ceiling) is
    /// `max` bytes.
    pub fn with_max_table_size(max: usize) -> Self {
        HpackDecoder {
            table: DynamicTable::new(max),
            size_limit: max,
        }
    }

    /// Decode one header block into its field list. Returns [`Error::Corrupt`]
    /// on any malformed representation, bad table index, or an over-limit
    /// size update; [`Error::UnexpectedEnd`] on truncation.
    pub fn decode(&mut self, block: &[u8]) -> Result<Vec<HeaderField>, Error> {
        let mut fields = Vec::new();
        let mut pos = 0;
        while pos < block.len() {
            let b = block[pos];
            if b & 0x80 != 0 {
                // §6.1 indexed header field.
                let (idx, np) = decode_int(block, pos, 7)?;
                pos = np;
                if idx == 0 {
                    return Err(Error::Corrupt);
                }
                let (n, v) = self.table.get(idx).ok_or(Error::Corrupt)?;
                fields.push(HeaderField::new(n, v));
            } else if b & 0x40 != 0 {
                // §6.2.1 literal with incremental indexing.
                let (name, value, np) = self.read_literal(block, pos, 6)?;
                pos = np;
                self.table.insert(&name, &value);
                fields.push(HeaderField {
                    name,
                    value,
                    sensitive: false,
                });
            } else if b & 0x20 != 0 {
                // §6.3 dynamic table size update.
                let (new_max, np) = decode_int(block, pos, 5)?;
                pos = np;
                if new_max > self.size_limit {
                    return Err(Error::Corrupt);
                }
                self.table.set_max_size(new_max);
            } else {
                // §6.2.2 (without indexing) or §6.2.3 (never indexed). Both
                // have a 4-bit prefix; bit 0x10 distinguishes "never indexed".
                let sensitive = b & 0x10 != 0;
                let (name, value, np) = self.read_literal(block, pos, 4)?;
                pos = np;
                fields.push(HeaderField {
                    name,
                    value,
                    sensitive,
                });
            }
        }
        Ok(fields)
    }

    /// Read a literal field's name (indexed or string) and value (string)
    /// starting at `pos`. `prefix` is the index field's prefix width.
    fn read_literal(
        &self,
        block: &[u8],
        pos: usize,
        prefix: u32,
    ) -> Result<(Vec<u8>, Vec<u8>, usize), Error> {
        let (idx, mut p) = decode_int(block, pos, prefix)?;
        let name = if idx == 0 {
            let (n, np) = read_string(block, p)?;
            p = np;
            n
        } else {
            let (n, _) = self.table.get(idx).ok_or(Error::Corrupt)?;
            n.to_vec()
        };
        let (value, np) = read_string(block, p)?;
        Ok((name, value, np))
    }

    /// Current dynamic table size limit (for tests/inspection).
    #[cfg(test)]
    pub(crate) fn table_max_size(&self) -> usize {
        self.table.max_size()
    }
}

/// Read an HPACK string literal (§5.2) at `pos`: H-flagged 7-bit length, then
/// that many octets, Huffman-decoded if H was set.
fn read_string(block: &[u8], pos: usize) -> Result<(Vec<u8>, usize), Error> {
    let first = *block.get(pos).ok_or(Error::UnexpectedEnd)?;
    let huff = first & 0x80 != 0;
    let (len, p) = decode_int(block, pos, 7)?;
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
