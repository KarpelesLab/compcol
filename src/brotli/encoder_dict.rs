//! Encoder-side static dictionary matcher (RFC 7932 §8).
//!
//! Builds a hash index from the 13,504-word static dictionary and uses
//! it to find dictionary references at each input position. We only
//! consider transforms of `Tr::Identity` kind — those just wrap the
//! word with a fixed prefix/suffix, which is straightforward to verify
//! against the input. The Uppercase* and Shift* transforms would
//! require trial-decoding into a scratch buffer per candidate; the
//! identity transforms already cover the most-frequent natural-text
//! patterns (`"word"`, `"word "`, `" word "`, `". word"`, etc.) and
//! that's enough to put a sizable dent in the encoded size.
//!
//! The hash table is built lazily and reused across meta-blocks.
//! Memory cost is ~13,504 entries plus a 16-bit hash bucket array
//! (32 K entries), tens of KiB total.

use alloc::boxed::Box;
use alloc::vec::Vec;

use super::dictionary::{self, MAX_DICTIONARY_WORD_LENGTH, MIN_DICTIONARY_WORD_LENGTH};
use super::transforms::{PREFIX_SUFFIX, TRANSFORMS, Tr};

const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;
const NIL: u16 = u16::MAX;

/// Total number of dictionary words across all length classes.
/// 13,504 = 2^14 + ε.
const NUM_WORDS: usize = compute_num_words();

const fn compute_num_words() -> usize {
    let mut total = 0usize;
    let mut len = MIN_DICTIONARY_WORD_LENGTH;
    while len <= MAX_DICTIONARY_WORD_LENGTH {
        let bits = dictionary::SIZE_BITS_BY_LENGTH[len];
        if bits > 0 {
            total += 1usize << bits;
        }
        len += 1;
    }
    total
}

/// Packed (length, word_idx) — length in low 5 bits, word_idx in upper.
/// Max length 24 fits in 5 bits; max word_idx (1<<10 = 1024) fits in 11 bits.
#[derive(Clone, Copy, Debug)]
struct WordRef(u32);

impl WordRef {
    const fn new(len: u8, idx: u32) -> Self {
        Self((idx << 5) | (len as u32 & 0x1F))
    }
    fn len(self) -> u8 {
        (self.0 & 0x1F) as u8
    }
    fn idx(self) -> u32 {
        self.0 >> 5
    }
}

/// Dictionary hash index. `head[h]` points into `entries[]` via `prev`-
/// chained slots. Each slot is a `(WordRef, next_idx)` pair.
pub(crate) struct DictIndex {
    head: Box<[u16; HASH_SIZE]>,
    entries: Box<[(WordRef, u16)]>,
}

impl core::fmt::Debug for DictIndex {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("DictIndex")
            .field("hash_size", &HASH_SIZE)
            .field("entries", &self.entries.len())
            .finish()
    }
}

fn hash4(b0: u8, b1: u8, b2: u8, b3: u8) -> u32 {
    let v = (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24);
    v.wrapping_mul(0x9E37_79B1) >> (32 - HASH_BITS)
}

impl DictIndex {
    /// Build the dictionary index. Iterates all 13,504 words, hashes
    /// their first 4 bytes, and threads them into the hash table.
    pub(crate) fn build() -> Self {
        let mut head: Box<[u16; HASH_SIZE]> = Box::new([NIL; HASH_SIZE]);
        let mut entries: Vec<(WordRef, u16)> = Vec::with_capacity(NUM_WORDS);

        for len in MIN_DICTIONARY_WORD_LENGTH..=MAX_DICTIONARY_WORD_LENGTH {
            let bits = dictionary::SIZE_BITS_BY_LENGTH[len];
            if bits == 0 {
                continue;
            }
            let count = 1u32 << bits;
            for idx in 0..count {
                let word = match dictionary::word(len, idx) {
                    Some(w) => w,
                    None => continue,
                };
                if word.len() < 4 {
                    continue;
                }
                let h = hash4(word[0], word[1], word[2], word[3]);
                let bucket = h as usize;
                let entry_idx = entries.len();
                // Cap at u16::MAX - 1 to fit the NIL sentinel.
                if entry_idx >= u16::MAX as usize {
                    // Should not happen — NUM_WORDS == 13504.
                    break;
                }
                let prev = head[bucket];
                head[bucket] = entry_idx as u16;
                entries.push((WordRef::new(len as u8, idx), prev));
            }
        }

        Self {
            head,
            entries: entries.into_boxed_slice(),
        }
    }

    /// Iterate the bucket for `input[..4]`, calling `f(word_len, word_idx, word_bytes)`.
    fn for_each_candidate<F: FnMut(u8, u32, &'static [u8])>(&self, key: &[u8], mut f: F) {
        if key.len() < 4 {
            return;
        }
        let h = hash4(key[0], key[1], key[2], key[3]);
        let mut cur = self.head[h as usize];
        // Bound chain traversal to avoid pathological buckets.
        let mut steps = 0usize;
        while cur != NIL && steps < 32 {
            let (wref, next) = self.entries[cur as usize];
            let len = wref.len();
            let idx = wref.idx();
            if let Some(w) = dictionary::word(len as usize, idx) {
                f(len, idx, w);
            }
            cur = next;
            steps += 1;
        }
    }
}

/// What sort of body transform applies to the dictionary word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BodyKind {
    /// Word emitted verbatim.
    Identity,
    /// First ASCII letter of the word is upper-cased.
    UppercaseFirstAscii,
    /// The last `N` bytes of the word are dropped before emission. `N`
    /// is in 1..=9. Supported by [`find_dict_match`] but the default
    /// transform table omits these (see `identity_transforms`).
    #[allow(dead_code)]
    OmitLast(u8),
}

/// Identity / UppercaseFirst-transform table cache. We pre-extract the
/// prefix + suffix byte strings for every transform whose kind is one
/// of those two, so the matcher loop touches contiguous tables instead
/// of `match`-dispatching per word.
#[derive(Clone, Copy, Debug)]
pub(crate) struct IdTransform {
    pub(crate) id: u8,
    pub(crate) prefix: &'static [u8],
    pub(crate) suffix: &'static [u8],
    pub(crate) body: BodyKind,
}

/// Build the list of identity- and (ASCII) UppercaseFirst-style
/// transforms. Other transform kinds (`OmitFirst/Last`, `UppercaseAll`,
/// shift) are skipped — they're either rare or non-trivial to invert
/// from a raw input byte. The two kinds we keep cover the most
/// frequent natural-text patterns (verbatim word and capitalised
/// sentence-start word).
pub(crate) fn identity_transforms() -> Vec<IdTransform> {
    let mut v = Vec::with_capacity(128);
    for (id, &(pre, kind, suf)) in TRANSFORMS.iter().enumerate() {
        let body = match kind {
            Tr::Identity => BodyKind::Identity,
            Tr::UppercaseFirst => BodyKind::UppercaseFirstAscii,
            // OmitLastN transforms are technically supported (see
            // `find_dict_match`) but in practice didn't pay for the
            // extra distance-tree cost on the benchmark corpus, so we
            // skip them by default. Re-enable by uncommenting:
            //     Tr::OmitLast1 => BodyKind::OmitLast(1),
            //     ...
            _ => continue,
        };
        v.push(IdTransform {
            id: id as u8,
            prefix: PREFIX_SUFFIX[pre as usize],
            suffix: PREFIX_SUFFIX[suf as usize],
            body,
        });
    }
    v
}

/// One match candidate produced by [`find_dict_match`].
#[derive(Clone, Copy, Debug)]
pub(crate) struct DictMatch {
    /// Dictionary word length, in 4..=24 — goes into the `copy_len` field
    /// of the brotli command.
    pub(crate) word_len: u8,
    /// In-bucket word index.
    pub(crate) word_idx: u32,
    /// Transform id, in 0..121.
    pub(crate) transform_id: u8,
    /// Total bytes consumed from the input by this match (= prefix.len()
    /// + word_len + suffix.len()).
    pub(crate) emit_len: u32,
}

/// Search for a dictionary reference at `input[pos..]`. Returns the
/// longest emit_len found, ties broken by smaller (word_len, transform_id)
/// for stable behaviour.
///
/// Constraints: word_len must be in `[MIN_DICTIONARY_WORD_LENGTH,
/// MAX_DICTIONARY_WORD_LENGTH]` AND the dictionary class for that length
/// must be non-empty.
pub(crate) fn find_dict_match(
    index: &DictIndex,
    transforms: &[IdTransform],
    input: &[u8],
    pos: usize,
    min_emit_len: u32,
) -> Option<DictMatch> {
    if pos >= input.len() {
        return None;
    }
    let tail = &input[pos..];

    let mut best: Option<DictMatch> = None;
    let mut best_len: u32 = min_emit_len.saturating_sub(1);

    for tr in transforms {
        let pre = tr.prefix;
        let suf = tr.suffix;
        // Need at least prefix + MIN_DICTIONARY_WORD_LENGTH + suffix bytes.
        if tail.len() < pre.len() + MIN_DICTIONARY_WORD_LENGTH + suf.len() {
            continue;
        }
        // Verify prefix.
        if !tail.starts_with(pre) {
            continue;
        }
        let after_pre = &tail[pre.len()..];
        if after_pre.len() < 4 {
            continue;
        }

        // For UppercaseFirst, the first byte of the emitted body is
        // `to_uppercase(word[0])`. We only handle the ASCII case here:
        // word[0] is an ASCII lowercase letter and emitted byte is
        // word[0] ^ 32. So the input byte must be an ASCII uppercase
        // letter; we lowercase it to recover the dictionary's first
        // byte before hashing.
        //
        // For OmitLast(N), the emitted body is `word[..wl - N]`. The
        // hash key is the input's first 4 bytes (which equal the
        // word's first 4 bytes only when `wl - N >= 4`; we skip if
        // not, since shorter emitted bodies can't be hashed reliably
        // here).
        let (key_first, body_offset_first_byte) = match tr.body {
            BodyKind::Identity => (after_pre[0], 0u8),
            BodyKind::UppercaseFirstAscii => {
                if !after_pre[0].is_ascii_uppercase() {
                    continue;
                }
                (after_pre[0] | 0x20, 32u8)
            }
            BodyKind::OmitLast(_) => (after_pre[0], 0u8),
        };
        let key = [key_first, after_pre[1], after_pre[2], after_pre[3]];
        let body_kind = tr.body;

        // Look up candidates whose first 4 bytes hash to the same bucket
        // as `key`. Hash collisions are possible, so we verify byte-by-
        // byte below.
        index.for_each_candidate(&key, |word_len, word_idx, word| {
            let wl = word_len as usize;
            // Compute the emitted body length (= bytes of input consumed
            // for the word body, before suffix).
            let body_len = match body_kind {
                BodyKind::Identity | BodyKind::UppercaseFirstAscii => wl,
                BodyKind::OmitLast(n) => {
                    let n = n as usize;
                    if wl <= n + 3 {
                        // After omission the body would be < 4 bytes;
                        // not worth checking — the hash isn't valid for
                        // such short bodies and the match would be
                        // tiny anyway.
                        return;
                    }
                    wl - n
                }
            };
            if after_pre.len() < body_len + suf.len() {
                return;
            }
            // Verify the body's first byte.
            if after_pre[0] ^ body_offset_first_byte != word[0] {
                return;
            }
            if body_len > 1 && !after_pre[1..body_len].eq(&word[1..body_len]) {
                return;
            }
            // Verify the suffix.
            if !suf.is_empty() && !after_pre[body_len..body_len + suf.len()].eq(suf) {
                return;
            }
            let emit_len = (pre.len() + body_len + suf.len()) as u32;
            if emit_len > best_len {
                best_len = emit_len;
                best = Some(DictMatch {
                    word_len,
                    word_idx,
                    transform_id: tr.id,
                    emit_len,
                });
            }
        });
    }

    best
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_does_not_panic() {
        let _ = DictIndex::build();
    }

    #[test]
    fn find_time_at_zero() {
        // The first word in the dictionary is "time" (length 4, idx 0).
        // Transform 0 is `(49, Identity, 49)` — i.e. pure identity.
        let index = DictIndex::build();
        let trs = identity_transforms();
        let input = b"time";
        let m = find_dict_match(&index, &trs, input, 0, 4).expect("should find 'time'");
        assert_eq!(m.word_len, 4);
        assert_eq!(m.word_idx, 0);
        assert_eq!(m.emit_len, 4);
    }

    #[test]
    fn find_time_space_suffix() {
        // "time " — should pick transform 1 (= 49, Identity, 0 = "" + word + " ").
        let index = DictIndex::build();
        let trs = identity_transforms();
        let input = b"time ";
        let m = find_dict_match(&index, &trs, input, 0, 4).expect("should find 'time '");
        assert!(m.emit_len >= 4);
    }
}
