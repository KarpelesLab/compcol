//! QPACK dynamic table — RFC 9204 §3.2.
//!
//! The dynamic table is a FIFO of `(name, value)` entries with byte-size
//! accounting (§3.2.1: each entry costs `name.len() + value.len() + 32`).
//! Entries are addressed by an **absolute index** that is assigned at insertion
//! and never changes: the first inserted entry is absolute index 0, the next 1,
//! and so on. Eviction drops the lowest absolute indices. The number of
//! insertions ever performed is the *Insert Count* (§2.1.4), which equals the
//! absolute index of the next entry to be inserted.
//!
//! Field-section and encoder-stream instructions reference entries with
//! *relative* and *post-base* indices, which this module converts to absolute
//! indices (see [`DynamicTable::relative_to_absolute`] and
//! [`DynamicTable::post_base_to_absolute`]).

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::vec::Vec;

/// Per-entry overhead added to name+value lengths for size accounting
/// (RFC 9204 §3.2.1).
pub(crate) const ENTRY_OVERHEAD: usize = 32;

/// QPACK dynamic table. `entries` holds live entries oldest-first; the oldest
/// live entry has absolute index `dropped` (the count of evicted entries), and
/// the youngest has absolute index `insert_count - 1`.
#[derive(Debug, Default)]
pub(crate) struct DynamicTable {
    entries: VecDeque<(Vec<u8>, Vec<u8>)>,
    /// Current byte size (sum of entry sizes).
    size: usize,
    /// Current capacity (max byte size). Starts at 0 — the encoder must send a
    /// Set Dynamic Table Capacity instruction before any insert (§3.2.3).
    capacity: usize,
    /// Total number of entries ever inserted (the Insert Count, §2.1.4).
    insert_count: usize,
    /// Total number of entries ever evicted (absolute index of the oldest live
    /// entry, or of the next insert if the table is empty).
    dropped: usize,
}

impl DynamicTable {
    pub(crate) fn new() -> Self {
        DynamicTable::default()
    }

    /// Entry byte cost per §3.2.1.
    pub(crate) fn entry_size(name: &[u8], value: &[u8]) -> usize {
        name.len() + value.len() + ENTRY_OVERHEAD
    }

    /// The Insert Count: number of entries ever inserted (§2.1.4). Also the
    /// absolute index that the next inserted entry will receive.
    pub(crate) fn insert_count(&self) -> usize {
        self.insert_count
    }

    /// Current byte size of the table.
    #[cfg(test)]
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    /// Current capacity.
    #[cfg(test)]
    pub(crate) fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of live entries.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Set the table capacity (§3.2.3), evicting entries as needed. Returns
    /// `false` if `new_capacity` exceeds `max` (the caller's connection limit).
    pub(crate) fn set_capacity(&mut self, new_capacity: usize, max: usize) -> bool {
        if new_capacity > max {
            return false;
        }
        self.capacity = new_capacity;
        self.evict_to_fit(0);
        true
    }

    fn evict_to_fit(&mut self, incoming: usize) {
        while self.size + incoming > self.capacity {
            match self.entries.pop_front() {
                Some((n, v)) => {
                    self.size -= Self::entry_size(&n, &v);
                    self.dropped += 1;
                }
                None => break,
            }
        }
    }

    /// Whether an entry of `(name, value)` can be inserted given the current
    /// capacity and live contents (§3.2.2: an insert that cannot fit even after
    /// evicting everything is an error). Used by the decoder to reject bad
    /// encoder streams.
    pub(crate) fn can_insert(&self, name: &[u8], value: &[u8]) -> bool {
        Self::entry_size(name, value) <= self.capacity
    }

    /// Insert `(name, value)` at the next absolute index (§3.2.2), evicting
    /// older entries as needed. Returns the absolute index assigned, or `None`
    /// if the entry cannot fit even in an empty table at the current capacity.
    pub(crate) fn insert(&mut self, name: &[u8], value: &[u8]) -> Option<usize> {
        let need = Self::entry_size(name, value);
        if need > self.capacity {
            return None;
        }
        self.evict_to_fit(need);
        let abs = self.insert_count;
        self.entries.push_back((name.to_vec(), value.to_vec()));
        self.size += need;
        self.insert_count += 1;
        Some(abs)
    }

    /// Look up an entry by **absolute** index. Returns `None` if the index has
    /// been evicted or never inserted.
    pub(crate) fn get_absolute(&self, abs: usize) -> Option<(&[u8], &[u8])> {
        if abs < self.dropped || abs >= self.insert_count {
            return None;
        }
        self.entries
            .get(abs - self.dropped)
            .map(|(n, v)| (n.as_slice(), v.as_slice()))
    }

    /// Convert a relative index (used on the encoder stream and in
    /// Duplicate/Insert-with-Name-Reference: relative to the most recent
    /// insertion) to an absolute index. Relative index 0 is the newest entry,
    /// i.e. absolute `insert_count - 1` (§3.2.5).
    pub(crate) fn relative_to_absolute_encoder(&self, rel: usize) -> Option<usize> {
        // abs = insert_count - 1 - rel
        let top = self.insert_count.checked_sub(1)?;
        top.checked_sub(rel)
    }

    /// Convert a relative index in a field section (relative to `base`) to an
    /// absolute index. Relative index 0 is `base - 1` (§3.2.5).
    pub(crate) fn field_relative_to_absolute(base: usize, rel: usize) -> Option<usize> {
        // abs = base - rel - 1
        base.checked_sub(rel)?.checked_sub(1)
    }

    /// Convert a post-base index in a field section to an absolute index.
    /// Post-base index 0 is `base` (§3.2.6).
    pub(crate) fn post_base_to_absolute(base: usize, idx: usize) -> Option<usize> {
        base.checked_add(idx)
    }
}
