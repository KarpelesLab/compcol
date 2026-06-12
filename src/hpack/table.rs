//! HPACK index address space — RFC 7541 §2.3.
//!
//! A single index space overlays the static table (indices 1..=61, RFC 7541
//! Appendix A) and the dynamic table (indices 62.., newest entry first,
//! §2.3.3). The dynamic table is a FIFO with byte-size accounting and
//! eviction (§4).

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Static table (RFC 7541 Appendix A), 61 `(name, value)` entries. Index 1
/// is `STATIC_TABLE[0]`.
#[rustfmt::skip]
pub(crate) const STATIC_TABLE: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

/// Number of static entries; the first dynamic index is `STATIC_LEN + 1`.
pub(crate) const STATIC_LEN: usize = STATIC_TABLE.len();

/// Per-entry overhead added to name+value lengths for size accounting
/// (RFC 7541 §4.1).
const ENTRY_OVERHEAD: usize = 32;

/// A reference to an index in the combined static+dynamic space, plus
/// whether the value (not just the name) matched.
pub(crate) struct Match {
    pub index: usize,
    pub value_matched: bool,
}

/// HPACK dynamic table: newest entry at the front. Size is bounded by
/// `max_size` (the connection's table-size limit); inserting evicts from the
/// back until the new entry fits (§4.4).
#[derive(Debug)]
pub(crate) struct DynamicTable {
    entries: VecDeque<(Vec<u8>, Vec<u8>)>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    pub fn new(max_size: usize) -> Self {
        DynamicTable {
            entries: VecDeque::new(),
            size: 0,
            max_size,
        }
    }

    #[cfg(test)]
    pub fn max_size(&self) -> usize {
        self.max_size
    }

    /// Apply a dynamic-table size update (§6.3), evicting as needed.
    pub fn set_max_size(&mut self, new_max: usize) {
        self.max_size = new_max;
        self.evict_to_fit(0);
    }

    fn entry_size(name: &[u8], value: &[u8]) -> usize {
        name.len() + value.len() + ENTRY_OVERHEAD
    }

    fn evict_to_fit(&mut self, incoming: usize) {
        while self.size + incoming > self.max_size {
            match self.entries.pop_back() {
                Some((n, v)) => self.size -= Self::entry_size(&n, &v),
                None => break,
            }
        }
    }

    /// Insert a new entry at the front (§4.4). If it is larger than the whole
    /// table, the table ends up empty (the spec result of evicting everything).
    pub fn insert(&mut self, name: &[u8], value: &[u8]) {
        let need = Self::entry_size(name, value);
        self.evict_to_fit(need);
        if need <= self.max_size {
            self.entries.push_front((name.to_vec(), value.to_vec()));
            self.size += need;
        }
    }

    /// Look up a 1-based combined index. Returns `(name, value)`.
    pub fn get(&self, index: usize) -> Option<(&[u8], &[u8])> {
        if index == 0 {
            return None;
        }
        if index <= STATIC_LEN {
            let (n, v) = STATIC_TABLE[index - 1];
            return Some((n, v));
        }
        let dyn_pos = index - STATIC_LEN - 1;
        self.entries
            .get(dyn_pos)
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
    }

    /// Find the best index for `(name, value)`: prefer a full name+value
    /// match, falling back to a name-only match. Searches the static table
    /// first (so the canonical low indices win), then the dynamic table.
    pub fn find(&self, name: &[u8], value: &[u8]) -> Option<Match> {
        let mut name_only: Option<usize> = None;
        for (i, (n, v)) in STATIC_TABLE.iter().enumerate() {
            if *n == name {
                if *v == value {
                    return Some(Match {
                        index: i + 1,
                        value_matched: true,
                    });
                }
                name_only.get_or_insert(i + 1);
            }
        }
        for (pos, (n, v)) in self.entries.iter().enumerate() {
            if n.as_slice() == name {
                let index = STATIC_LEN + 1 + pos;
                if v.as_slice() == value {
                    return Some(Match {
                        index,
                        value_matched: true,
                    });
                }
                name_only.get_or_insert(index);
            }
        }
        name_only.map(|index| Match {
            index,
            value_matched: false,
        })
    }
}
