//! Self-adjusting "lookup byte" cache used by RAR1.
//!
//! `XADRAR15Handle.m` maintains three 256-entry tables (`flagtable`,
//! `literaltable`, `offsettable`) plus their `reverse` companions. Each
//! entry packs `(value << 8) | rank`. Looking up an index returns the
//! `value`, then promotes the entry one step closer to the front of its
//! frequency band — a coarse move-to-front that lets the static Huffman
//! tables (`huffmancode0..4`) waste fewer code bits on hot bytes.
//!
//! The behaviour we mirror:
//!
//! 1. `ResetTable` partitions the 256 entries into 8 groups of 32. Each
//!    group's low byte starts at `7 - group_index`, so the table reads
//!    `7,7,…,7, 6,6,…,6, …, 0,0,…,0` with each value appearing 32 times.
//!    `reverse[0..6]` starts so that the next-slot pointer for each bucket
//!    lands at the bottom of its group.
//! 2. `LookupByte(index)` reads the packed entry, takes its low byte
//!    `bucket`, computes `target = (reverse[bucket]++ )`, swaps
//!    `table[index]` and `table[target]`, increments the moved entry's
//!    rank, and returns the original `value`. When `bucket` would tick
//!    past `limit` the table is reset.
//!
//! The exact `limit` per table and the per-table "value to swap into a slot
//! after reset" details are not 100% nailed down in our reverse-engineered
//! reference — what we replicate here is the structural skeleton plus the
//! observation that the table converges toward "most-frequently-seen
//! values cluster at the front". The shape is enough to plug into the
//! main RAR1 decode loop once the static Huffman tables are in place,
//! and the unit tests cover the deterministic reset / swap behaviour.

// Building-block; consumer is the future RAR1 state machine.
#![allow(dead_code)]

/// Side of a 256-entry symbol cache: the table + the reverse pointers.
///
/// `table[i]` packs `(value << 8) | rank`. `reverse[b]` records the next
/// promotion slot for bucket `b` and is incremented after each lookup.
///
/// `bucket_uses[b]` counts the number of lookups that landed in bucket `b`
/// since the last reset. When any bucket's count reaches `limit` the whole
/// table is reinitialised.
#[derive(Debug, Clone)]
pub struct LookupTable {
    table: [u16; 256],
    reverse: [u16; 256],
    /// Per-bucket "uses since reset" counter.
    bucket_uses: [u16; 256],
    /// Reset threshold per bucket.
    limit: u16,
}

impl LookupTable {
    /// Build a fresh table with the eight-group reset pattern.
    ///
    /// `initial_value` chooses what each entry's high byte holds:
    /// - `LookupKind::Identity` → `value = index` (the `literaltable`
    ///   and `offsettable` initial shape — `i << 8`).
    /// - `LookupKind::Complement` → `value = (-index) & 0xff` (the
    ///   `flagtable` initial shape — `((-i) & 0xff) << 8`).
    ///
    /// `limit` is the reset threshold. The original code uses 32 (= group
    /// size), which means a bucket can be touched 31 times before the
    /// table is wiped.
    pub fn new(kind: LookupKind, limit: u16) -> Self {
        let mut t = Self {
            table: [0u16; 256],
            reverse: [0u16; 256],
            bucket_uses: [0u16; 256],
            limit,
        };
        t.reset_table(kind);
        t
    }

    fn reset_table(&mut self, kind: LookupKind) {
        // Partition 256 entries into 8 groups of 32. Group `g` (0..8) gets
        // low byte `7 - g`, so the bucket sequence across the table is:
        //   indices   0.. 31 → bucket 7
        //   indices  32.. 63 → bucket 6
        //   indices  64.. 95 → bucket 5
        //   ...                              ↓
        //   indices 224..255 → bucket 0
        for (i, slot) in self.table.iter_mut().enumerate() {
            let group = i / 32;
            let bucket = 7 - group as u16;
            let value: u16 = match kind {
                LookupKind::Identity => i as u16,
                LookupKind::Complement => (256u16.wrapping_sub(i as u16)) & 0xFF,
            };
            *slot = (value << 8) | bucket;
        }
        // `reverse[b]` points at the first slot of bucket `b`'s group:
        //   bucket 0 → index 224
        //   bucket 1 → index 192
        //   bucket 2 → index 160
        //   ...
        //   bucket 7 → index 0
        for b in 0u16..8 {
            self.reverse[b as usize] = (7 - b) * 32;
        }
        // Buckets 8..256 are unused; zeroed already.
        for u in self.bucket_uses.iter_mut() {
            *u = 0;
        }
    }

    /// Read the value at `index`, promoting it within its bucket.
    ///
    /// Returns the high byte of `table[index]`. As a side-effect, swaps the
    /// entry with `table[reverse[bucket]]`, increments the moved entry's
    /// rank, and increments `reverse[bucket]`. If `reverse[bucket]` hits
    /// `limit`, the table is reset (we re-initialise the same `kind` we
    /// were constructed with — callers building from a single immutable
    /// trade-off don't need to call this themselves).
    pub fn lookup(&mut self, kind: LookupKind, index: u8) -> u8 {
        let idx = index as usize;
        let entry = self.table[idx];
        let value_byte = (entry >> 8) as u8;
        let bucket = (entry & 0xFF) as usize;

        let target = self.reverse[bucket] as usize;
        // Promote: swap `table[idx]` with `table[target]`, then bump the
        // moved-into-position entry's rank counter by 1.
        if target != idx {
            self.table.swap(idx, target);
        }
        // After the swap the entry that *was* at `idx` now lives at `target`.
        // Bump its low byte rank (saturating at 0xff is fine; the original
        // code never relies on huge counts, only on relative ordering).
        let bumped = self.table[target];
        let bumped_low = bumped & 0xFF;
        let new_low = bumped_low.saturating_add(1).min(0xFF);
        self.table[target] = (bumped & 0xFF00) | new_low;

        // Advance the bucket's reverse pointer and use counter.
        self.reverse[bucket] = self.reverse[bucket].wrapping_add(1);
        self.bucket_uses[bucket] = self.bucket_uses[bucket].saturating_add(1);
        if self.bucket_uses[bucket] >= self.limit {
            // Bucket saturated → wipe and start over.
            self.reset_table(kind);
        }

        value_byte
    }

    /// Snapshot of the current table for debugging / tests.
    #[cfg(test)]
    pub fn raw_table(&self) -> [u16; 256] {
        self.table
    }

    /// Snapshot of the reverse pointers for debugging / tests.
    #[cfg(test)]
    pub fn raw_reverse(&self) -> [u16; 256] {
        self.reverse
    }
}

/// How the high byte (the actual returned value) is initialised on every
/// table reset.
#[derive(Debug, Clone, Copy)]
pub enum LookupKind {
    /// `value = index`. Matches `literaltable[i] = i << 8` and the
    /// post-`ResetTable` shape of `offsettable`.
    Identity,
    /// `value = (-index) & 0xff`. Matches
    /// `flagtable[i] = ((-i) & 0xff) << 8`.
    Complement,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_initial_values() {
        let t = LookupTable::new(LookupKind::Identity, 32);
        // Every slot's high byte is its index, regardless of bucket.
        for i in 0..256u16 {
            let v = t.raw_table()[i as usize] >> 8;
            assert_eq!(v, i, "slot {i}");
        }
    }

    #[test]
    fn complement_initial_values() {
        let t = LookupTable::new(LookupKind::Complement, 32);
        for i in 0..256u16 {
            let v = t.raw_table()[i as usize] >> 8;
            let expected = (256u16.wrapping_sub(i)) & 0xFF;
            assert_eq!(v, expected, "slot {i}");
        }
    }

    #[test]
    fn group_bucket_assignment() {
        // 256 slots / 8 groups = 32 per group. Bucket of group g is 7-g.
        let t = LookupTable::new(LookupKind::Identity, 32);
        for i in 0..256u16 {
            let group = i / 32;
            let bucket_expected = 7 - group;
            let bucket_actual = t.raw_table()[i as usize] & 0xFF;
            assert_eq!(bucket_actual, bucket_expected, "slot {i}");
        }
    }

    #[test]
    fn reverse_pointers_start_at_group_start() {
        let t = LookupTable::new(LookupKind::Identity, 32);
        for b in 0u16..8 {
            // Bucket 0 → group 7 (last) → start at index 224.
            // Bucket 7 → group 0 (first) → start at index 0.
            let expected_start = (7 - b) * 32;
            assert_eq!(t.raw_reverse()[b as usize], expected_start, "bucket {b}");
        }
    }

    #[test]
    fn lookup_returns_value_byte() {
        let mut t = LookupTable::new(LookupKind::Identity, 32);
        // First lookup at index 5 returns the high byte of table[5], which
        // is 5 (Identity).
        assert_eq!(t.lookup(LookupKind::Identity, 5), 5);
    }

    #[test]
    fn lookup_promotes_within_bucket() {
        // With Identity init, slot 100 has value 100 and bucket = 7 - 3 = 4.
        // bucket 4's reverse pointer starts at (7 - 4) * 32 = 96.
        // First lookup: returns 100, then swaps slots 100 and 96, bumps
        // reverse[4] to 97.
        let mut t = LookupTable::new(LookupKind::Identity, 32);
        assert_eq!(t.raw_reverse()[4], 96);
        let got = t.lookup(LookupKind::Identity, 100);
        assert_eq!(got, 100);
        // Slot 96 now holds the (former) slot-100 entry; its value should
        // still be 100, but its rank low byte is bumped.
        let s96 = t.raw_table()[96];
        assert_eq!(s96 >> 8, 100);
        // Slot 100 holds the (former) slot-96 entry — value 96.
        let s100 = t.raw_table()[100];
        assert_eq!(s100 >> 8, 96);
        // reverse[4] has advanced.
        assert_eq!(t.raw_reverse()[4], 97);
    }

    #[test]
    fn lookup_resets_when_limit_reached() {
        // limit=2 → after two lookups in the same bucket the table resets.
        let mut t = LookupTable::new(LookupKind::Identity, 2);
        // Bucket 4 (= 7-3) lives in slots 96..128. Start: reverse[4] = 96.
        let _ = t.lookup(LookupKind::Identity, 96); // reverse[4] -> 97
        // After this second lookup, reverse[4] ticks past `limit` → reset.
        let _ = t.lookup(LookupKind::Identity, 97);
        // Reset state matches a fresh table.
        let fresh = LookupTable::new(LookupKind::Identity, 2);
        assert_eq!(t.raw_table(), fresh.raw_table());
        assert_eq!(t.raw_reverse(), fresh.raw_reverse());
    }

    #[test]
    fn first_lookup_of_each_bucket_is_stable() {
        // Looking up the first slot of each bucket (index 0 in each
        // group) returns the bucket's first value and nothing dramatic
        // happens to the table structure (the swap is a no-op when
        // target == idx).
        let mut t = LookupTable::new(LookupKind::Identity, 32);
        // Bucket 7's reverse pointer starts at 0. Slot 0 has value 0,
        // bucket 7 → lookup returns 0 and swaps slot 0 with slot 0.
        assert_eq!(t.lookup(LookupKind::Identity, 0), 0);
        // Slot 0's value is still 0; rank bumped.
        let s0 = t.raw_table()[0];
        assert_eq!(s0 >> 8, 0);
        assert_eq!(s0 & 0xFF, 8); // bucket 7 + 1 rank
    }
}
