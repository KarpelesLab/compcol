# Security Policy

## Threat model

`compcol` is a library for **decoding compressed data from untrusted
sources** (network endpoints, archive readers, file scanners). Its
decoders are written to that bar:

- **No panic, no out-of-bounds reads on malformed input.** Decoders use
  checked arithmetic and bounds-checked indexing; malformed streams are
  rejected with an [`Error`] variant rather than aborting the process.
- **No memory-unsafety.** The crate is `#![forbid(unsafe_code)]`
  crate-wide, so there is no `unsafe` to misuse — a decoder bug cannot
  become a memory-safety bug.
- **Decompression-bomb resistance.** A sub-kilobyte stream can expand to
  many gigabytes. Callers handling untrusted input **must** bound the
  decoded output:
  - Wrap any decoder in [`compcol::limit::LimitedDecoder`], which aborts
    with `Error::OutputLimitExceeded` once a byte budget is exceeded; it
    composes with `compcol::io` and the factory's boxed decoders.
  - For the one-shot `compcol::vec` helpers, **avoid the unbounded
    `decompress_to_vec` / `decompress_to_vec_with`** on untrusted data —
    use `decompress_to_vec_capped` / `decompress_to_vec_capped_with`,
    which take an explicit output cap.

  An output limit bounds the bytes a decoder **hands out**, not the memory
  it works in. Most decoders stream and keep only their window, but a few
  build a block or the whole result internally before the caller sees a
  byte, so the limit fires only after that memory is committed:

  | Codec | What is held regardless of the output limit |
  |---|---|
  | `rar2`, `rar3` | the whole declared output of a member |
  | `snappy`, `huffman`, `bwt` | the whole decoded block (snappy: at most ~21× the input) |
  | `sit13`, `arsenic` | the whole fork, up to 256 MiB |
  | `ppmd` (7z-style) | the whole output, up to 64 MiB |
  | `lz5` | one decoded block, up to 256 MiB for the largest block code |
  | `ppmd`, `ppmd-zip`, `rar3` | a model arena sized by the stream header, up to 256 MiB |

  For these, also bound the **input** size and the number of concurrent
  decodes, or do not expose them to untrusted data.

These are the only guarantees claimed: no panic, no undefined behavior,
and bomb-bounded decode when the caller supplies a limit. The crate does
**not** claim that every encoder is constant-time, side-channel-free, or
suitable for cryptographic use.

## Reporting a vulnerability

Please report security issues **privately** — do not open a public issue
for a vulnerability.

- Preferred: use GitHub's private vulnerability reporting on the
  repository — **Security → Report a vulnerability**
  (<https://github.com/KarpelesLab/compcol/security/advisories/new>).
- This opens a private advisory visible only to the maintainers; we will
  coordinate a fix and disclosure with you there.

A panic, out-of-bounds access, or unbounded allocation reachable from a
decoder on malformed input is in scope and is treated as a security bug.

## Supported versions

Only the latest published release on
[crates.io](https://crates.io/crates/compcol) receives security fixes.
