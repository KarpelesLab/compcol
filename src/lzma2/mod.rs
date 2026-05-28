//! LZMA2 — chunked container around LZMA used as the inner format of `.xz`.
//!
//! Reference: <https://tukaani.org/xz/xz-file-format.txt> (section 5.3.1 plus
//! the `xz-embedded` / liblzma source for the chunk-level layout, which the
//! `.xz` spec defers to).
//!
//! An LZMA2 stream is a sequence of chunks, each introduced by a single
//! **control byte**:
//!
//! | control       | meaning                                                  |
//! |---------------|----------------------------------------------------------|
//! | `0x00`        | end-of-stream marker, no more chunks                     |
//! | `0x01`        | uncompressed chunk, dictionary reset                     |
//! | `0x02`        | uncompressed chunk, no reset                             |
//! | `0x80..=0xFF` | LZMA-compressed chunk (state/dict reset bits in 5..=7)   |
//!
//! Any other value is malformed.
//!
//! **Uncompressed chunk header** (3 bytes total, then raw data):
//!
//! ```text
//! +------+-------+-------+----------- ... -----------+
//! | ctrl | size1 | size0 |        raw bytes          |
//! +------+-------+-------+----------- ... -----------+
//! ```
//!
//! `size1`/`size0` form a 16-bit **big-endian** value equal to
//! `uncompressed_size - 1`, so a chunk carries between 1 and 65 536 bytes.
//!
//! **Compressed chunk header** (5 or 6 bytes, then compressed payload). The
//! lower five bits of the control byte plus two big-endian size bytes encode
//! `uncompressed_size - 1` (21 bits, up to 2 MiB); two further big-endian
//! bytes encode `compressed_size - 1` (16 bits, up to 64 KiB); a properties
//! byte follows if the control byte's reset flags require it.
//!
//! ## Status: stored-only encoder, full decoder for dict-reset chunks
//!
//! This iteration ships:
//!
//! * a **decoder** that handles uncompressed LZMA2 streams (control bytes
//!   `0x00`, `0x01`, `0x02`) and compressed chunks whose control byte
//!   requests a dictionary reset (`0xE0..=0xFF`, i.e. state reset + new
//!   properties + dictionary reset). Compressed chunks without dictionary
//!   reset (`0x80..=0xDF`) are rare in xz-utils output and return
//!   [`Error::Unsupported`]. Invalid control bytes return [`Error::Corrupt`].
//! * an **encoder** that emits *only* type-`0x01` chunks (uncompressed,
//!   dictionary reset), capped at 64 KiB of uncompressed data per chunk,
//!   followed by a `0x00` end-of-stream marker on `finish`.
//!
//! ## How the compressed-chunk path works
//!
//! Each `0xE0..=0xFF` chunk in LZMA2 is a self-contained LZMA stream (state
//! reset + dictionary reset means no probability or history is shared across
//! chunks). The chunk header tells us the uncompressed and compressed sizes
//! and a single LZMA properties byte; the chunk payload is a range-coded LZMA
//! body with no trailing EOS marker.
//!
//! Rather than duplicate the ~700-line LZMA core here, we **synthesise a
//! 13-byte legacy `.lzma` ("alone") header** in memory — `[props,
//! dict_size_LE32, uncompressed_size_LE64]` — and drive a fresh
//! [`crate::lzma::Decoder`] with that header followed by the chunk payload.
//! Since the synthesised uncompressed size matches the chunk, the inner
//! decoder finishes precisely when the chunk's bytes are out. The inner
//! decoder is constructed once and reset between chunks.
//!
//! The fake-header approach was chosen over inlining a second copy of the
//! LZMA decoder because it adds tens of lines instead of hundreds and only
//! ever needs to support the dict-reset case — the only case we accept here.

extern crate alloc;
use alloc::boxed::Box;

use crate::error::Error;
use crate::traits::{Algorithm, Decoder as DecoderTrait, Encoder as EncoderTrait, Progress};

/// Largest payload an encoder will pack into a single 0x01 chunk.
/// The spec allows up to 65 536 (2^16) bytes per uncompressed chunk; staying
/// at 65 536 maximises bytes per header byte triple.
const ENC_CHUNK_SIZE: usize = 65_536;

/// Zero-sized marker type implementing [`Algorithm`] for LZMA2.
#[derive(Debug, Clone, Copy, Default)]
pub struct Lzma2;

impl Algorithm for Lzma2 {
    const NAME: &'static str = "lzma2";
    type Encoder = Encoder;
    type Decoder = Decoder;

    fn encoder() -> Encoder {
        Encoder::new()
    }
    fn decoder() -> Decoder {
        Decoder::new()
    }
}

// ─── decoder ──────────────────────────────────────────────────────────────

/// State machine for parsing a compressed-chunk header. After the control
/// byte we need 2 size bytes (uncompressed) + 2 size bytes (compressed)
/// + an optional 1 properties byte, then the LZMA payload itself.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct CompHeader {
    /// Top 5 bits of the 21-bit uncompressed-size-minus-1 from the control byte.
    unc_top5: u32,
    /// Whether the control byte's reset flags require a new properties byte.
    needs_props: bool,
    /// Bytes-read counter, drives the sub-phase below.
    read: u8,
    /// Bytes of the size header that we've already read (0..=4).
    /// 0..=1: filling `unc_low_hi`, `unc_low_lo`
    /// 2..=3: filling `cmp_hi`, `cmp_lo`
    unc_low_hi: u8,
    unc_low_lo: u8,
    cmp_hi: u8,
    cmp_lo: u8,
    /// Buffered properties byte, valid once `read >= 5 && needs_props`.
    props: u8,
}

impl CompHeader {
    /// Once `read` has advanced past the size + props bytes, return the
    /// computed uncompressed-size, compressed-size, and props.
    fn unpack(&self) -> (u32, u32, u8) {
        let unc_low = ((self.unc_low_hi as u32) << 8) | (self.unc_low_lo as u32);
        let unc = (self.unc_top5 << 16) | unc_low;
        let cmp = ((self.cmp_hi as u32) << 8) | (self.cmp_lo as u32);
        (unc + 1, cmp + 1, self.props)
    }
}

enum DecPhase {
    /// Waiting for the next chunk's control byte.
    Control,
    /// Read the control byte for an uncompressed chunk; need 2 more bytes for
    /// the big-endian `(size - 1)` field.
    UncompSize { ctrl: u8, idx: u8, hi: u8 },
    /// Streaming out `remaining` raw bytes of an uncompressed chunk.
    UncompData { remaining: u32 },
    /// Reading the size + (optional) props bytes that follow a compressed
    /// chunk's control byte.
    CompHdr(CompHeader),
    /// Streaming the LZMA payload of a compressed chunk through `inner`.
    /// `cmp_remaining` is how many compressed-stream bytes we still owe the
    /// inner decoder; `unc_remaining` is how many output bytes we still owe
    /// the caller. Once `cmp_remaining` hits zero we switch into
    /// `CompDrain` to call `inner.finish()` — the inner LZMA decoder
    /// otherwise stalls at the tail because its packet gate requires
    /// `REQUIRED_INPUT_MAX` (20) bytes of look-ahead.
    CompData {
        cmp_remaining: u32,
        unc_remaining: u32,
    },
    /// All compressed bytes have been fed to `inner`; drain the rest of
    /// its output via `inner.finish()`. `unc_remaining` is the bytes the
    /// chunk still owes the caller.
    CompDrain { unc_remaining: u32 },
    /// Hit the `0x00` end-of-stream marker; nothing more to read or emit.
    Done,
}

/// Streaming LZMA2 decoder.
///
/// Handles uncompressed chunks (`0x01`, `0x02`) and compressed chunks that
/// reset the dictionary (`0xE0..=0xFF`). Compressed chunks without a
/// dictionary reset (`0x80..=0xDF`) currently return [`Error::Unsupported`].
pub struct Decoder {
    phase: DecPhase,
    poisoned: bool,
    /// Inner LZMA decoder used to decode compressed chunks. Constructed
    /// lazily on first compressed chunk to keep the empty-stream path
    /// allocation-free; reset between chunks.
    inner: Option<Box<crate::lzma::Decoder>>,
}

impl Decoder {
    pub const fn new() -> Self {
        Self {
            phase: DecPhase::Control,
            poisoned: false,
            inner: None,
        }
    }

    fn poison(&mut self, e: Error) -> Error {
        self.poisoned = true;
        e
    }

    /// Bootstrap the inner LZMA decoder for a single compressed chunk:
    /// reset it and prime it with a synthesised 13-byte `.lzma` header
    /// containing the chunk's properties byte and an exact-size trailer.
    fn prime_inner(&mut self, props: u8, uncompressed: u32) -> Result<(), Error> {
        // Validate the LZMA properties byte the same way the LZMA decoder
        // does, so we surface a clean error before reset.
        if props >= 9 * 5 * 5 {
            return Err(Error::BadHeader);
        }

        // Construct the synthetic `.lzma` header:
        //   byte 0:     props
        //   bytes 1-4:  dict size, little-endian. Sized to cover the chunk;
        //               the inner decoder clamps below 4096 and above 64 MiB.
        //   bytes 5-12: uncompressed size, little-endian.
        // We pick `dict_size = max(uncompressed, 4096)`: every backreference
        // in this chunk must land within the bytes we've already produced
        // for this chunk (state + dict were both reset), so the chunk's own
        // size is a safe upper bound on any in-chunk distance.
        let dict_size: u32 = uncompressed.max(4096);
        let unc_u64: u64 = uncompressed as u64;
        let mut header = [0u8; 13];
        header[0] = props;
        header[1..5].copy_from_slice(&dict_size.to_le_bytes());
        header[5..13].copy_from_slice(&unc_u64.to_le_bytes());

        let inner = self
            .inner
            .get_or_insert_with(|| Box::new(crate::lzma::Decoder::new()));
        inner.reset();
        // Feed the 13 header bytes with no output room. The inner decoder
        // accepts the bytes into its internal buffer and returns Progress
        // without writing anything (header parse happens lazily on the next
        // decode() call once range-coder bytes are available).
        let mut nothing: [u8; 0] = [];
        let p = inner.decode(&header, &mut nothing)?;
        // The inner decoder absorbs all bytes we hand it into its own buffer.
        debug_assert_eq!(p.consumed, header.len());
        debug_assert_eq!(p.written, 0);
        Ok(())
    }
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl DecoderTrait for Decoder {
    fn decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }

        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            let initial_consumed = consumed;
            let initial_written = written;

            match self.phase {
                DecPhase::Control => {
                    if consumed == input.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let ctrl = input[consumed];
                    consumed += 1;
                    match ctrl {
                        0x00 => {
                            self.phase = DecPhase::Done;
                        }
                        0x01 | 0x02 => {
                            self.phase = DecPhase::UncompSize {
                                ctrl,
                                idx: 0,
                                hi: 0,
                            };
                        }
                        0xE0..=0xFF => {
                            // State reset + new properties + dictionary
                            // reset. We can decode these directly because
                            // every per-chunk LZMA state and dictionary is
                            // restarted.
                            self.phase = DecPhase::CompHdr(CompHeader {
                                unc_top5: (ctrl as u32) & 0x1F,
                                needs_props: true,
                                read: 0,
                                unc_low_hi: 0,
                                unc_low_lo: 0,
                                cmp_hi: 0,
                                cmp_lo: 0,
                                props: 0,
                            });
                        }
                        0x80..=0xDF => {
                            // 0x80..=0x9F: no reset (rare; would require us
                            //              to keep LZMA range/state alive
                            //              across chunks).
                            // 0xA0..=0xBF: state reset, keep old properties.
                            // 0xC0..=0xDF: state reset + new properties.
                            // None of these reset the dictionary, so we
                            // cannot honour them with a fresh LZMA decoder
                            // per chunk. Surface cleanly until we wire a
                            // persistent inner LZMA state.
                            return Err(self.poison(Error::Unsupported));
                        }
                        _ => {
                            // 0x03..=0x7F are not assigned by the spec.
                            return Err(self.poison(Error::Corrupt));
                        }
                    }
                }
                DecPhase::UncompSize { ctrl, idx, hi } => {
                    if consumed == input.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let b = input[consumed];
                    consumed += 1;
                    if idx == 0 {
                        self.phase = DecPhase::UncompSize {
                            ctrl,
                            idx: 1,
                            hi: b,
                        };
                    } else {
                        // size = ((hi << 8) | b) + 1, always in 1..=65_536.
                        let size = ((hi as u32) << 8) | (b as u32);
                        let size = size + 1;
                        self.phase = DecPhase::UncompData { remaining: size };
                    }
                }
                DecPhase::UncompData { remaining } => {
                    if remaining == 0 {
                        self.phase = DecPhase::Control;
                        continue;
                    }
                    if consumed == input.len() || written == output.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let in_left = input.len() - consumed;
                    let out_left = output.len() - written;
                    let n = core::cmp::min(remaining as usize, core::cmp::min(in_left, out_left));
                    output[written..written + n].copy_from_slice(&input[consumed..consumed + n]);
                    consumed += n;
                    written += n;
                    let new_remaining = remaining - n as u32;
                    self.phase = if new_remaining == 0 {
                        DecPhase::Control
                    } else {
                        DecPhase::UncompData {
                            remaining: new_remaining,
                        }
                    };
                }
                DecPhase::CompHdr(mut hdr) => {
                    // We need 4 size bytes; one props byte if needs_props.
                    let needed = if hdr.needs_props { 5 } else { 4 };
                    while hdr.read < needed && consumed < input.len() {
                        let b = input[consumed];
                        consumed += 1;
                        match hdr.read {
                            0 => hdr.unc_low_hi = b,
                            1 => hdr.unc_low_lo = b,
                            2 => hdr.cmp_hi = b,
                            3 => hdr.cmp_lo = b,
                            4 => hdr.props = b,
                            _ => unreachable!(),
                        }
                        hdr.read += 1;
                    }
                    if hdr.read < needed {
                        // Out of input; stash partial header back and ask
                        // the caller for more bytes.
                        self.phase = DecPhase::CompHdr(hdr);
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }

                    let (unc, cmp, props) = hdr.unpack();
                    self.prime_inner(props, unc).map_err(|e| self.poison(e))?;
                    self.phase = DecPhase::CompData {
                        cmp_remaining: cmp,
                        unc_remaining: unc,
                    };
                }
                DecPhase::CompData {
                    mut cmp_remaining,
                    mut unc_remaining,
                } => {
                    if unc_remaining == 0 {
                        // Chunk produced everything it owes the caller; the
                        // inner decoder may still have trailing bytes
                        // buffered (range-coder normalisation), but they
                        // can't yield output past `uncompressed_size`. Skip
                        // straight to the next chunk header.
                        self.phase = DecPhase::Control;
                        continue;
                    }
                    if cmp_remaining == 0 {
                        // Fed everything the chunk header promised. The
                        // inner decoder's packet gate (REQUIRED_INPUT_MAX
                        // bytes of buffered look-ahead) would otherwise
                        // stall at the tail of the stream, so switch to
                        // finish() mode to disable it.
                        self.phase = DecPhase::CompDrain { unc_remaining };
                        continue;
                    }
                    if consumed == input.len() {
                        // Need more compressed bytes before we can
                        // continue.
                        self.phase = DecPhase::CompData {
                            cmp_remaining,
                            unc_remaining,
                        };
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    if written == output.len() {
                        self.phase = DecPhase::CompData {
                            cmp_remaining,
                            unc_remaining,
                        };
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }

                    let inner = match self.inner.as_mut() {
                        Some(i) => i,
                        None => {
                            // CompData is only entered after prime_inner
                            // sets self.inner; this is a logic error.
                            return Err(self.poison(Error::Corrupt));
                        }
                    };

                    // Feed at most cmp_remaining bytes; clamp output to
                    // unc_remaining so the inner decoder cannot over-produce.
                    let in_left = input.len() - consumed;
                    let feed = core::cmp::min(cmp_remaining as usize, in_left);
                    let out_room = core::cmp::min(unc_remaining as usize, output.len() - written);

                    let p = inner
                        .decode(
                            &input[consumed..consumed + feed],
                            &mut output[written..written + out_room],
                        )
                        .map_err(|e| self.poison(e))?;
                    consumed += p.consumed;
                    written += p.written;
                    cmp_remaining -= p.consumed as u32;
                    unc_remaining -= p.written as u32;

                    self.phase = DecPhase::CompData {
                        cmp_remaining,
                        unc_remaining,
                    };
                }
                DecPhase::CompDrain { mut unc_remaining } => {
                    if unc_remaining == 0 {
                        self.phase = DecPhase::Control;
                        continue;
                    }
                    if written == output.len() {
                        self.phase = DecPhase::CompDrain { unc_remaining };
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let inner = match self.inner.as_mut() {
                        Some(i) => i,
                        None => return Err(self.poison(Error::Corrupt)),
                    };
                    let out_room = core::cmp::min(unc_remaining as usize, output.len() - written);
                    let p = inner
                        .finish(&mut output[written..written + out_room])
                        .map_err(|e| self.poison(e))?;
                    written += p.written;
                    unc_remaining -= p.written as u32;
                    self.phase = DecPhase::CompDrain { unc_remaining };
                    // If the inner reports done but we still owe output,
                    // the stream was truncated relative to the chunk
                    // header — surface that as Corrupt because the LZMA2
                    // chunk lied about its uncompressed size.
                    if p.done && unc_remaining > 0 {
                        return Err(self.poison(Error::Corrupt));
                    }
                    if p.written == 0 && !p.done {
                        // Inner needs more space; bounce.
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                DecPhase::Done => {
                    return Ok(Progress {
                        consumed,
                        written,
                        done: false,
                    });
                }
            }

            if consumed == initial_consumed && written == initial_written {
                return Ok(Progress {
                    consumed,
                    written,
                    done: false,
                });
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        // Drain any pending data using an empty input slice.
        let empty: [u8; 0] = [];
        let p = self.decode(&empty, output)?;
        match self.phase {
            DecPhase::Done => Ok(Progress {
                consumed: 0,
                written: p.written,
                done: true,
            }),
            DecPhase::Control => {
                // No 0x00 marker was seen. The xz layer above us delimits the
                // stream by block size, so an "empty" finish here is legal
                // only if no chunks were started.
                Err(self.poison(Error::UnexpectedEnd))
            }
            _ => Err(self.poison(Error::UnexpectedEnd)),
        }
    }

    fn reset(&mut self) {
        self.phase = DecPhase::Control;
        self.poisoned = false;
        if let Some(inner) = self.inner.as_mut() {
            inner.reset();
        }
    }
}

// ─── encoder ──────────────────────────────────────────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum EncPhase {
    /// No partial chunk in flight; ready to start a new one or finish.
    Idle,
    /// Mid-header: writing 3 chunk-header bytes for a chunk that will carry
    /// `payload` total bytes of data, `header_idx` bytes of header already
    /// emitted.
    HeaderOut {
        payload: u32,
        header_idx: u8,
        header: [u8; 3],
    },
    /// Mid-payload: `remaining` bytes of the current chunk still need to be
    /// emitted into output (after being consumed from input).
    PayloadOut { remaining: u32 },
    /// `finish` was called; we still owe the `0x00` end-of-stream marker.
    NeedEosMarker,
    /// Finished; nothing more to emit.
    Done,
}

/// Streaming LZMA2 encoder. Emits only type-`0x01` (uncompressed, dictionary
/// reset) chunks plus a `0x00` end-of-stream marker — see the module header
/// for context.
pub struct Encoder {
    phase: EncPhase,
}

impl Encoder {
    pub const fn new() -> Self {
        Self {
            phase: EncPhase::Idle,
        }
    }
}

impl Default for Encoder {
    fn default() -> Self {
        Self::new()
    }
}

/// Build the 3-byte header for an uncompressed-type-0x01 chunk of `size`
/// bytes. `size` must satisfy `1 <= size <= 65_536`.
fn make_uncomp_header(size: u32) -> [u8; 3] {
    debug_assert!((1..=65_536).contains(&size));
    let v = size - 1; // fits in 16 bits.
    [0x01, ((v >> 8) & 0xFF) as u8, (v & 0xFF) as u8]
}

impl EncoderTrait for Encoder {
    fn encode(&mut self, input: &[u8], output: &mut [u8]) -> Result<Progress, Error> {
        let mut consumed = 0usize;
        let mut written = 0usize;

        loop {
            match self.phase {
                EncPhase::Idle => {
                    if consumed == input.len() {
                        // No more input on this call; just return.
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // Decide how big the next chunk should be. We commit
                    // *now* to a chunk of `payload` bytes, which must then
                    // be drained from the same input slice we were handed
                    // — otherwise we'd be writing a chunk header for bytes
                    // we won't actually carry. Since `payload` is capped
                    // at the bytes remaining in this input, that always
                    // works.
                    let remaining_in = input.len() - consumed;
                    let payload = core::cmp::min(remaining_in, ENC_CHUNK_SIZE) as u32;
                    let header = make_uncomp_header(payload);
                    self.phase = EncPhase::HeaderOut {
                        payload,
                        header_idx: 0,
                        header,
                    };
                }
                EncPhase::HeaderOut {
                    payload,
                    mut header_idx,
                    header,
                } => {
                    while (header_idx as usize) < 3 && written < output.len() {
                        output[written] = header[header_idx as usize];
                        written += 1;
                        header_idx += 1;
                    }
                    if (header_idx as usize) == 3 {
                        self.phase = EncPhase::PayloadOut { remaining: payload };
                    } else {
                        self.phase = EncPhase::HeaderOut {
                            payload,
                            header_idx,
                            header,
                        };
                        // Output is full and we still owe header bytes —
                        // can't make further progress on this call.
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                }
                EncPhase::PayloadOut { remaining } => {
                    if remaining == 0 {
                        self.phase = EncPhase::Idle;
                        continue;
                    }
                    if written == output.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    // We committed to `remaining` bytes of payload sourced
                    // from this input slice in the Idle branch above. If
                    // input is already drained we cannot honour that — that
                    // would only happen if the caller fed us through encode
                    // until input exhausted and then called encode again
                    // with a different (or empty) input, but inside this
                    // single call we always have the bytes we committed to.
                    if consumed == input.len() {
                        return Ok(Progress {
                            consumed,
                            written,
                            done: false,
                        });
                    }
                    let in_left = input.len() - consumed;
                    let out_left = output.len() - written;
                    let n = core::cmp::min(remaining as usize, core::cmp::min(in_left, out_left));
                    output[written..written + n].copy_from_slice(&input[consumed..consumed + n]);
                    consumed += n;
                    written += n;
                    let new_remaining = remaining - n as u32;
                    self.phase = if new_remaining == 0 {
                        EncPhase::Idle
                    } else {
                        EncPhase::PayloadOut {
                            remaining: new_remaining,
                        }
                    };
                }
                EncPhase::NeedEosMarker | EncPhase::Done => {
                    // Encoding after finish() is a misuse; refuse cleanly.
                    return Err(Error::Corrupt);
                }
            }
        }
    }

    fn finish(&mut self, output: &mut [u8]) -> Result<Progress, Error> {
        let mut written = 0usize;

        loop {
            match self.phase {
                EncPhase::Idle => {
                    self.phase = EncPhase::NeedEosMarker;
                }
                EncPhase::HeaderOut { .. } | EncPhase::PayloadOut { .. } => {
                    // The encode() above only ever returns mid-HeaderOut or
                    // mid-PayloadOut when its output buffer ran out. Calling
                    // finish() while a chunk is still in flight means the
                    // caller stopped delivering both bytes and output room
                    // before the chunk we committed to was fully written —
                    // a contract violation we surface as Corrupt rather
                    // than UnexpectedEnd, since the encoder has no input
                    // stream of its own that could be "ended" early.
                    return Err(Error::Corrupt);
                }
                EncPhase::NeedEosMarker => {
                    if written == output.len() {
                        return Ok(Progress {
                            consumed: 0,
                            written,
                            done: false,
                        });
                    }
                    output[written] = 0x00;
                    written += 1;
                    self.phase = EncPhase::Done;
                }
                EncPhase::Done => {
                    return Ok(Progress {
                        consumed: 0,
                        written,
                        done: true,
                    });
                }
            }
        }
    }

    fn reset(&mut self) {
        self.phase = EncPhase::Idle;
    }
}
