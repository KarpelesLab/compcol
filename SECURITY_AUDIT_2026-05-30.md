# compcol security audit — 2026-05-30

Parallel security audit of all codec families. Crate is pure-Rust,
`unsafe_code = "forbid"`, `no_std`+alloc. **Threat model is denial-of-service**
(panic / OOM / infinite loop) driven by malformed input to *decoders*, plus
local file-handling abuse in the CLI. There is no memory-corruption / RCE
surface (no `unsafe`).

## Confirmed, actionable findings

| # | Sev | Location | Class | Fix |
|---|-----|----------|-------|-----|
| 1 | HIGH | `src/zstd/literals.rs:~210` | subtraction underflow `last = regen_size - 3*per` in 4-stream Huffman literals when `regen_size % 4 ∈ {1,2}` → panic (debug) / unbounded alloc loop (release) | `regen_size.checked_sub(3*per).ok_or(Error::Corrupt)?`; reject `regen_size < 4` in 4-stream mode |
| 2 | HIGH | `src/xpress_huffman/decoder.rs:~274-284` | match distance validated vs whole-stream `output_emitted` but indexed into `self.decoded` which is cleared on drain → `usize` underflow / OOB panic on multi-block streams (also mis-decodes valid cross-block back-refs) | retain a 64 KiB sliding history and validate/index against it (mirror `src/xpress/decoder.rs`) |
| 3 | MED-HIGH | `src/lzfse/decoder.rs:~265` | `Vec::with_capacity(decoded_size)` from attacker `n_raw_bytes` (u32, up to 4 GiB); not covered by `LimitedDecoder` (alloc precedes any output) | drop the `with_capacity` (grow naturally) or cap to a small multiple of `payload_len` |
| 4 | MED | `src/lz5/block.rs` (check too late at `src/lz5/mod.rs:~684`) | compressed-block decode grows output unbounded before the size check; LZ4 linked-block (`src/lz4/frame.rs:1215,1254`) has the correct per-append cap | thread `max_block_raw` into the sequence loop, check before each append |
| 5 | MED | `src/bin/compcol.rs:~414-430` | non-`--force` output uses `create(true)` (non-atomic) + follows symlinks → TOCTOU / overwrite of a symlink target in attacker-writable dirs | use `OpenOptions::create_new(true)` for the non-force path, map AlreadyExists to the existing friendly error |
| 6 | LOW | `src/lzma/mod.rs:~865` | legacy `.lzma` decoder does not bound `lc+lp` (LZMA2 path does, `lc+lp<=4`); allows ~6.3 MB literal-table alloc from a 13-byte header | reject `lc + lp > 4` with `Error::BadHeader` |
| 7 | LOW | `src/brotli/mod.rs:~2279` | `max_dist = ….min(self.total_out as u32)` truncates after 4 GiB of output → distance mis-routing/early abort (memory-safe; correctness only) | compute `max_dist` in full width (usize/u64), no lossy `u32` cast |

## Lower-priority / by-design (flagged for human review, not auto-fixed)

- **zstd window/history not enforced** (`src/zstd/decoder.rs`): `Window_Size` /
  `Frame_Content_Size` parsed but never enforced; `history` retains the whole
  frame and offsets are validated vs `history.len()` not the window. Output
  amplification / unbounded retention. *Behavioral change — review before
  enforcing a window cap.*
- **zstd eager `with_capacity`** from header size fields
  (`literals.rs:86,185`, `sequences.rs:125`) — bounded amplification; partially
  addressed by capping capacity hints in fix #1's unit.
- **bzip2 quadratic re-decode on chunked input**
  (`src/bzip2/decoder.rs:133-174` + `429-510`): a block is decoded from scratch
  on every `step()` until fully buffered → Θ(n²) CPU when fed byte-by-byte.
  *Algorithmic-complexity DoS; fix requires resumable/throttled re-decode —
  review needed, not a one-line change.*
- **zip_reduce internal buffering up to `uncomp_len`** (`src/zip_reduce/mod.rs`):
  retains full decoded stream for back-refs; `LimitedDecoder` caps emitted (not
  internal) bytes. Recommend documenting / capping `uncomp_len` for untrusted
  input. *By-design trust model.*
- **RAR5 `bits.read(n)` with n up to ~26-30** reaching `debug_assert!(n <= 16)`
  (`src/rar5/...`): debug-only panic; in release the subsequent
  `dist > window_size` check prevents OOB. (RAR/PPMd re-audit was in progress.)

## Verified clean (no reachable DoS)

deflate / deflate64 / zlib / gzip; lzma + xz decoders (dict/window capped,
back-refs validated, varint bounded, LZMA2 framing); zstd FSE/Huffman/bitreader
and offset handling; brotli decode path (Huffman, context maps, dictionary,
transforms, distance); bzip2 BWT/MTF/RLE/Huffman/level/origin guards; lz4 (block
+ frame), snappy, lzo back-ref/length validation; lzw/lzss/zip_implode/
zip_shrink/zip_reduce (cycle defense, strict Kraft, follower-set bounds);
lzx/amiga_lzx/xpress(plain)/lznt1/quantum; lzfse LZVN copy/index, lzs, adc,
packbits, rle; lzham header rejection before alloc; shared `bits.rs`,
`huffman.rs`, `checksum.rs`, and `limit.rs` (the decompression-bomb guard is
sound — no overflow/underflow/write-before-check bypass).
