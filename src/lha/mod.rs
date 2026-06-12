//! LHA / LZH compression methods: `-lh1-`, `-lh2-`, `-lh4-`, `-lh5-`,
//! `-lh6-`, `-lh7-`.
//!
//! These are LZSS sliding-dictionary back-reference schemes whose
//! literal/length and position codes are Huffman-coded. They are the
//! *raw method payloads* — there is no LHA container header here, exactly
//! like the rar/zip-method codecs elsewhere in this crate.
//!
//! - `lh1`: 4 KiB dictionary, **adaptive** Huffman (the classic LZHUF
//!   scheme of Yoshizaki & Okumura), fixed position code.
//! - `lh2`: 8 KiB dictionary, **adaptive** Huffman for both literals/lengths
//!   *and* positions (see [`dynamic_huff`]).
//! - `lh4`: 4 KiB dictionary, static Huffman.
//! - `lh5`: 16 KiB dictionary, static Huffman — the dominant method.
//! - `lh6`: 64 KiB dictionary, static Huffman.
//! - `lh7`: 128 KiB dictionary, static Huffman.
//!
//! `lh4`/`lh5`/`lh6`/`lh7` share the static-Huffman block structure
//! (Okumura's public-domain ar002 layout — see [`static_huff`]) and differ
//! only in dictionary size and the number of position-code bits. `lh1`
//! uses the adaptive-Huffman tree-update scheme (see [`lzhuf`]); `lh2`
//! extends it to an 8 KiB window with an adaptive position tree (see
//! [`dynamic_huff`]).
//!
//! ## Framing — none
//!
//! These codecs read and write the **raw** method payload, exactly as stored
//! in a `.lzh`/`.lha` archive: no length prefix, no added framing. How the
//! decoder knows where the stream ends depends on the method (see
//! [`DecoderConfig`]):
//!
//! - `lh4`/`lh5`/`lh6`/`lh7` are block-structured and self-terminate — decode
//!   the input and call `finish()`, like any other codec here.
//! - `lh1` and `lh2` are continuous, size-terminated streams with no in-band
//!   end, so their decoders need the uncompressed length out of band via
//!   [`DecoderConfig::with_len`] (the size a container reader already has).
//!   `with_len` is accepted by every method and bounds decompressed size for
//!   decompression-bomb safety.
//!
//! ## Licensing
//!
//! Clean-room from public LZH / LZHUF format *descriptions* (Okumura's
//! LZHUF / ar002 algorithms are documented and were placed in the public
//! domain). No code or code-length tables were copied from LGPL
//! (The Unarchiver / XADMaster), GPL, or unRAR sources.
//!
//! ## What is validated
//!
//! Every method here round-trips arbitrary data through this crate's own
//! encoder and decoder (the encoders for `lh1` and `lh4`/`lh5`/`lh6`/`lh7`
//! are implemented, not stubbed). See `tests/lha.rs`.

#![cfg_attr(docsrs, doc(cfg(feature = "lha")))]

extern crate alloc;
use alloc::vec::Vec;

mod bits;
pub mod dynamic_huff;
mod huffman;
pub mod lzhuf;
pub mod static_huff;

use crate::error::Error;
use crate::traits::{Algorithm, RawDecoder, RawEncoder, RawProgress};

use static_huff::Params;

/// Which LHA method a codec instance implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Method {
    Lh1,
    Lh2,
    Lh4,
    Lh5,
    Lh6,
    Lh7,
}

impl Method {
    fn name(self) -> &'static str {
        match self {
            Method::Lh1 => "lh1",
            Method::Lh2 => "lh2",
            Method::Lh4 => "lh4",
            Method::Lh5 => "lh5",
            Method::Lh6 => "lh6",
            Method::Lh7 => "lh7",
        }
    }
    /// `lh4`/`lh5`/`lh6`/`lh7` use the static-Huffman block structure; `lh1`
    /// and `lh2` use adaptive (dynamic) Huffman.
    fn is_static(self) -> bool {
        !matches!(self, Method::Lh1 | Method::Lh2)
    }
}

// ─── decoder configuration ───────────────────────────────────────────────

/// Optional out-of-band uncompressed length for the decoder.
///
/// The decoder consumes the **raw** `-lh*-` method payload (exactly the bytes
/// stored in a `.lzh`/`.lha` archive — no length prefix, no extra framing):
///
/// - **Default (`expected_len: None`)** — stream-terminated. Decode the input
///   and call `finish()` at the end, like any other codec in this crate. This
///   works for the block-structured methods (`lh4`/`lh5`/`lh6`/`lh7`), which
///   self-terminate at the final block boundary. It does **not** work for
///   `lh1` (see below).
/// - **`with_len(n)`** — when the original size is known out of band (e.g.
///   from the LHA container header), the decoder stops at exactly `n` bytes
///   and never touches trailing padding. Required for `lh1`, and valid for
///   every method.
///
/// `lh1` (LZHUF) is a continuous, size-terminated code stream with no in-band
/// end marker, so decoding it **requires** `with_len`; a default (`None`)
/// `lh1` decoder returns [`Error::Unsupported`] on non-empty input rather than
/// emit trailing garbage from padding bits.
#[derive(Debug, Clone, Copy, Default)]
pub struct DecoderConfig {
    /// Uncompressed size from the container header, if known out of band.
    pub expected_len: Option<usize>,
}

impl DecoderConfig {
    /// Config for decoding a raw `-lh*-` payload whose uncompressed size is
    /// known out of band (the common container-reader case).
    pub fn with_len(expected_len: usize) -> Self {
        Self {
            expected_len: Some(expected_len),
        }
    }
}

// ─── marker types ────────────────────────────────────────────────────────

macro_rules! define_method {
    ($marker:ident, $variant:ident, $name:literal, $doc:literal) => {
        #[doc = $doc]
        #[derive(Debug, Clone, Copy, Default)]
        pub struct $marker;

        impl Algorithm for $marker {
            const NAME: &'static str = $name;
            type Encoder = Encoder;
            type Decoder = Decoder;
            type EncoderConfig = ();
            type DecoderConfig = DecoderConfig;
            fn encoder_with(_: ()) -> Encoder {
                Encoder::new(Method::$variant)
            }
            fn decoder_with(config: DecoderConfig) -> Decoder {
                Decoder::with_config(Method::$variant, config)
            }
        }
    };
}

define_method!(
    Lh1,
    Lh1,
    "lh1",
    "LHA `-lh1-`: 4 KiB dictionary, adaptive Huffman (LZHUF)."
);
define_method!(
    Lh2,
    Lh2,
    "lh2",
    "LHA `-lh2-`: 8 KiB dictionary, adaptive Huffman for literals/lengths and positions."
);
define_method!(
    Lh4,
    Lh4,
    "lh4",
    "LHA `-lh4-`: 4 KiB dictionary, static Huffman."
);
define_method!(
    Lh5,
    Lh5,
    "lh5",
    "LHA `-lh5-`: 16 KiB dictionary, static Huffman."
);
define_method!(
    Lh6,
    Lh6,
    "lh6",
    "LHA `-lh6-`: 64 KiB dictionary, static Huffman."
);
define_method!(
    Lh7,
    Lh7,
    "lh7",
    "LHA `-lh7-`: 128 KiB dictionary, static Huffman."
);

// ─── encoder ─────────────────────────────────────────────────────────────

/// Streaming LHA encoder.
///
/// Buffers all input, then produces the encoded payload in `raw_finish`
/// (the Huffman tables are built from full-stream statistics, so the
/// whole input is needed before any byte is emitted — the same approach
/// the [`lzss`](crate::lzss) encoder uses). Memory cost is `O(input)`.
#[derive(Debug)]
pub struct Encoder {
    method: Method,
    input: Vec<u8>,
    output: Vec<u8>,
    out_cursor: usize,
    finalized: bool,
}

impl Encoder {
    fn new(method: Method) -> Self {
        Self {
            method,
            input: Vec::new(),
            output: Vec::new(),
            out_cursor: 0,
            finalized: false,
        }
    }

    fn finalize(&mut self) {
        let payload = match self.method {
            Method::Lh1 => lzhuf::encode_payload(&self.input),
            Method::Lh2 => dynamic_huff::encode_payload(&self.input),
            _ => {
                let params = Params::for_method(self.method.name());
                static_huff::encode_payload(&self.input, params)
            }
        };
        self.output.extend_from_slice(&payload);
    }
}

impl RawEncoder for Encoder {
    fn raw_encode(&mut self, input: &[u8], _output: &mut [u8]) -> Result<RawProgress, Error> {
        self.input.extend_from_slice(input);
        Ok(RawProgress {
            consumed: input.len(),
            written: 0,
            done: false,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.finalized {
            self.finalize();
            self.finalized = true;
        }
        let remaining = self.output.len() - self.out_cursor;
        let take = remaining.min(output.len());
        output[..take].copy_from_slice(&self.output[self.out_cursor..self.out_cursor + take]);
        self.out_cursor += take;
        Ok(RawProgress {
            consumed: 0,
            written: take,
            done: self.out_cursor >= self.output.len(),
        })
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.out_cursor = 0;
        self.finalized = false;
    }
}

// ─── decoder ─────────────────────────────────────────────────────────────

/// Streaming LHA decoder.
///
/// Buffers all input (a single bit-stream that can't be decoded
/// incrementally without re-implementing the bit reader as a resumable
/// state machine across every Huffman code), decodes it in one pass once
/// the stream ends, then drains the decoded bytes into the caller's
/// output across calls. Output size is bounded by the 4-byte length
/// header, so a crafted small input cannot expand without limit.
#[derive(Debug)]
pub struct Decoder {
    method: Method,
    /// Uncompressed size supplied out of band; `None` selects the legacy
    /// 4-byte-length-prefix framing (see [`DecoderConfig`]).
    expected_len: Option<usize>,
    input: Vec<u8>,
    /// Decoded output buffer, produced lazily once enough input is
    /// available (or at `raw_finish`).
    output: Vec<u8>,
    out_cursor: usize,
    decoded: bool,
}

impl Decoder {
    fn with_config(method: Method, config: DecoderConfig) -> Self {
        Self {
            method,
            expected_len: config.expected_len,
            input: Vec::new(),
            output: Vec::new(),
            out_cursor: 0,
            decoded: false,
        }
    }

    /// Decode the buffered raw `-lh*-` payload into `self.output`. Idempotent.
    fn decode_all(&mut self) -> Result<(), Error> {
        if self.decoded {
            return Ok(());
        }
        let payload = &self.input[..];

        self.output = if self.method.is_static() {
            // lh4/5/6/7 are block-structured: each block declares its code
            // count, so the decoder self-terminates when the bitstream ends
            // at a block boundary. `expected_len`, when supplied, just stops
            // it earlier (and avoids touching trailing padding).
            let params = Params::for_method(self.method.name());
            static_huff::decode_payload(payload, self.expected_len, params)?
        } else {
            // lh1 (LZHUF) and lh2 are continuous, size-terminated code streams
            // with no in-band end marker — the uncompressed length must be
            // supplied out of band via `DecoderConfig::with_len`. Without it
            // we cannot know where the data ends (the trailing bits are
            // padding), so we refuse rather than emit garbage.
            match self.expected_len {
                Some(n) => match self.method {
                    Method::Lh2 => dynamic_huff::decode_payload(payload, n)?,
                    _ => lzhuf::decode_payload(payload, n)?,
                },
                None if payload.is_empty() => Vec::new(),
                None => return Err(Error::Unsupported),
            }
        };
        self.decoded = true;
        Ok(())
    }

    fn drain(&mut self, output: &mut [u8]) -> RawProgress {
        let remaining = self.output.len() - self.out_cursor;
        let take = remaining.min(output.len());
        output[..take].copy_from_slice(&self.output[self.out_cursor..self.out_cursor + take]);
        self.out_cursor += take;
        RawProgress {
            consumed: 0,
            written: take,
            done: self.out_cursor >= self.output.len(),
        }
    }
}

impl RawDecoder for Decoder {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if !self.decoded {
            // Still accumulating the compressed stream. We can't know the
            // stream has ended until `raw_finish`, so buffer and report
            // input consumed with no output yet.
            self.input.extend_from_slice(input);
            return Ok(RawProgress {
                consumed: input.len(),
                written: 0,
                done: false,
            });
        }
        // Already decoded: drain. (Input after decode is unexpected; we
        // ignore it, consuming nothing.)
        let p = self.drain(output);
        Ok(RawProgress {
            consumed: 0,
            written: p.written,
            done: p.done,
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        // Empty stream (no input at all): treat as zero-length output.
        if !self.decoded && self.input.is_empty() {
            self.decoded = true;
        }
        self.decode_all()?;
        Ok(self.drain(output))
    }

    fn raw_reset(&mut self) {
        self.input.clear();
        self.output.clear();
        self.out_cursor = 0;
        self.decoded = false;
    }
}
