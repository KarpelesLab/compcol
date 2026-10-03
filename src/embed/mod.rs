//! Embedded-target mode — the `embed` feature.
//!
//! With `embed` enabled, the algorithms that have a small variant are built
//! as that variant **under their usual names**: `compcol::gzip::Gzip`,
//! `compcol::zlib::Encoder`, `compcol::deflate::Decoder` and so on keep their
//! paths and their [`Encoder`](crate::Encoder) / [`Decoder`](crate::Decoder)
//! contracts, so the same downstream code compiles either way. What changes
//! is what is behind them: no heap, little stack, little code.
//!
//! `embed` is a *mode*, not an addition. It pulls nothing in by itself (no
//! `alloc`), and is meant for `--no-default-features --features embed,gzip`
//! style builds. Enabling it in a crate graph switches every user of that
//! graph to the small variants, as Cargo features unify.
//!
//! # The deflate family: `deflate`, `zlib`, `gzip`
//!
//! A decoder in the manner of zlib's `puff`, which decodes Huffman codes one
//! bit at a time from the count of codes of each length, and a greedy LZ77
//! encoder over a single-probe hash table, coded with deflate's fixed
//! Huffman codes. (The code was absorbed from the author's `minizlib` crate,
//! since retired.) Each of the three modules has them two ways:
//!
//! - **Streaming**, behind the usual `Encoder` / `Decoder`: the decoder
//!   takes its input in pieces of any size and keeps about 1.1 KiB of state
//!   between them, besides its history window; the encoder gathers its
//!   input a block at a time. Their sizes are picked at build time:
//!   `Decoder` is `WindowedDecoder<{ WINDOW }>` and `Encoder` is
//!   `BlockEncoder<{ BLOCK }, { TABLE }>`, and
//!   `gzip::WindowedDecoder::<4096>` or `gzip::BlockEncoder::<16384, 4096>`
//!   are as good.
//! - **One shot**, `embed` build only: `decompress(input, output)` decodes a
//!   whole stream from one slice into another, which doubles as the history
//!   window, so it needs no window and keeps no state;
//!   `decompressed_len(input, max_len)` only counts; and `compress(input,
//!   table, output)` makes one block of a whole slice, with a hash table of
//!   the caller's of any size.
//!
//! And **at the lowest level**, `embed::flate`, the API of `minizlib`: the
//! caller's own memory throughout (the output buffer or a window of any
//! size as history, a table of any size to compress with), input pulled
//! through a callback or an iterator or pushed, output to a buffer, a
//! callback or a mere count, and a richer error type of its own.
//!
//! What it gives up compared to the standard build:
//!
//! - **Ratio.** The encoder emits fixed-Huffman blocks only, finds matches
//!   within a block only, and does no lazy matching. With the default
//!   [`BLOCK`] and [`TABLE`], expect roughly 40–45 % on text where `gzip -6`
//!   gets 20 %; 32 KiB blocks and a 4096-entry table get to about 34 %.
//!   `EncoderConfig::level` is accepted and ignored.
//! - **Speed.** The decoder runs at tens of MB/s where the standard one does
//!   hundreds; small code was the goal.
//! - **Sync flush.** [`Encoder::flush`](crate::Encoder::flush) returns
//!   [`Error::Unsupported`](crate::Error::Unsupported): the encoder cannot
//!   byte-align its bitstream mid-stream. Use `finish`.
//! - **Preset dictionaries** (zlib `FDICT`) are not supported, and
//!   `zlib::DecoderConfig` has no `dictionary` field.
//! - **Window size.** The streaming decoder's window is inline, its size
//!   fixed by its type; `deflate::DecoderConfig::window_size` only tightens
//!   the distance check. A window smaller than [`WINDOW`] only decodes the
//!   streams whose back-references stay within it.
//!
//! # Memory
//!
//! Nothing is allocated, so the streaming codecs hold everything they need,
//! and are big: place them in a `static`, in a `Box` if there is an
//! allocator, or on a stack that has the room. Both constructors are `const
//! fn` and build an all-zero state, so `static DEC: Decoder =
//! Decoder::new()` is possible (behind the `Mutex`, `RefCell` or `static
//! mut` of your platform's choosing), lands in `.bss`, costs no flash, and
//! nothing transits the stack. An unoptimised `Box::new(Decoder::new())`
//! does build the struct on the stack first.
//!
//! | struct                          | size (bytes)                  | of which                          |
//! |---------------------------------|------------------------------:|-----------------------------------|
//! | `*::Decoder`                    | ≈ 33 850 (≤ [`DECODER_SIZE`]) | 32 KiB window + ~1.1 KiB codes/state |
//! | `*::WindowedDecoder<W>`         | ≈ W + 1 080                   | the window + the same             |
//! | `*::Encoder`                    | ≈ 6 170 (≤ [`ENCODER_SIZE`])  | 4 KiB block + 2 KiB table         |
//! | `*::BlockEncoder<B, T>`         | ≈ B + 2 T + 30                | the block + the table             |
//!
//! The streaming codecs use a few hundred bytes of stack per call. The
//! one-shot functions keep their state there instead: `decompress` and
//! `decompressed_len` about 1.3 KiB, for the codes of the current block,
//! and `compress` about a hundred bytes, the table being the caller's.
//!
//! # Sizes CI holds the build to
//!
//! `tools/footprint/check.sh` builds a bare-metal `thumbv7em-none-eabi`
//! binary around each codec with `opt-level = "z"` and LTO, and fails if any
//! of these is exceeded, if any panic machinery gets linked, if any static
//! RAM is needed besides the codec struct itself, or if that struct does not
//! land in `.bss`:
//!
//! | configuration                       | code (bytes) | stack (bytes) |
//! |-------------------------------------|-------------:|--------------:|
//! | gzip decode                         | ≤ 4 000      | ≤ 352         |
//! | zlib decode                         | ≤ 4 000      | ≤ 352         |
//! | raw deflate decode                  | ≤ 3 400      | ≤ 352         |
//! | gzip encode                         | ≤ 1 850      | ≤ 256         |
//! | zlib encode                         | ≤ 1 850      | ≤ 256         |
//! | raw deflate encode                  | ≤ 1 500      | ≤ 224         |
//! | gzip encode + decode                | ≤ 6 200      | ≤ 416         |
//! | gzip decode, 4 KiB window           | ≤ 4 000      | ≤ 352         |
//! | gzip encode, 1 KiB block, 256 table | ≤ 1 850      | ≤ 256         |
//! | gzip `decompress`                   | ≤ 2 400      | ≤ 1 400       |
//! | zlib `decompress`                   | ≤ 2 200      | ≤ 1 400       |
//! | raw deflate `decompress`            | ≤ 2 000      | ≤ 1 400       |
//! | gzip `decompressed_len`             | ≤ 2 200      | ≤ 1 400       |
//! | gzip `compress`                     | ≤ 1 000      | ≤ 160         |
//! | zlib `compress`                     | ≤ 950        | ≤ 160         |
//! | raw deflate `compress`              | ≤ 800        | ≤ 160         |
//! | `flate`: `gunzip`, buffer out     | ≤ 2 550      | ≤ 1 450       |
//! | `flate`: `gunzip`, streams        | ≤ 2 900      | ≤ 1 600       |
//! | `flate`: `gunzip_len`             | ≤ 2 400      | ≤ 1 450       |
//! | `flate`: `Decompressor`           | ≤ 3 650      | ≤ 1 500       |
//! | `flate`: `gzip`, buffer out       | ≤ 1 050      | ≤ 192         |
//! | `flate`: `Compressor`, streams    | ≤ 1 450      | ≤ 840         |
//! | `flate`: `BufferedCompressor`     | ≤ 1 600      | ≤ 448         |
//!
//! "Stack" is the deepest call path from the entry point, every function's
//! frame read off the disassembly (`tools/footprint/stack.py`); nothing
//! recurses and nothing is called indirectly, so it is the bound. Measured
//! on rustc 1.98: streaming decoders at 3 200–3 800 bytes of code and about
//! 330 of stack, streaming encoders at 1 350–1 750 and about 210, the
//! one-shot decoders at 1 850–2 250 and 1 340, the one-shot encoders at
//! 750–950 and 125. The table is a contract, not a report; the constants in
//! this module are the same ceilings for the host-side tests. The `flate`
//! rows include the stack of the program around them (a 512-byte chunk for
//! the `Compressor`, 64-byte buffers elsewhere), not that of the input and
//! output callbacks, the only calls made through a pointer.
#![cfg_attr(docsrs, doc(cfg(feature = "embed")))]

#[cfg(feature = "deflate")]
mod checksum;
#[cfg(feature = "deflate")]
pub(crate) mod decoder;
#[cfg(feature = "deflate")]
pub(crate) mod encoder;
#[cfg(feature = "deflate")]
pub mod flate;
#[cfg(feature = "deflate")]
pub(crate) mod format;
#[cfg(feature = "deflate")]
mod inflate;
#[cfg(feature = "deflate")]
pub(crate) mod oneshot;

/// The streaming decoder's history window by default, in bytes: deflate's
/// full 32 KiB reach, so every stream decodes. The most a
/// `WindowedDecoder` can have.
pub const WINDOW: usize = 32 * 1024;

/// The streaming encoder's block size by default, in bytes: input is
/// compressed a block at a time, and matches are only found within a block.
pub const BLOCK: usize = 4 * 1024;

/// The streaming encoder's hash table by default, in entries of `u16`.
pub const TABLE: usize = 1024;

/// Ceiling on `size_of::<Decoder>()` for the deflate-family decoders, in
/// bytes, with the default window. Asserted by the test suite.
pub const DECODER_SIZE: usize = WINDOW + 2048;

/// Ceiling on `size_of::<Encoder>()` for the deflate-family encoders, in
/// bytes, with the default sizes. Asserted by the test suite.
pub const ENCODER_SIZE: usize = BLOCK + 2 * TABLE + 128;

/// Defines the public codecs of a deflate-family module in `embed` mode,
/// around [`encoder::Encoder`] / [`decoder::Decoder`] in the given
/// [`format::Format`], and its one-shot functions. The module supplies
/// `EncoderConfig` and `DecoderConfig`, and `$window` maps the latter to the
/// decoder's window-size setting.
#[cfg(feature = "deflate")]
macro_rules! codec {
    ($format:ty, $window:expr) => {
        /// The streaming encoder, with the default sizes: blocks of
        /// [`BLOCK`](crate::embed::BLOCK) bytes, a table of
        /// [`TABLE`](crate::embed::TABLE) entries. See [`BlockEncoder`] to
        /// pick others.
        pub type Encoder = BlockEncoder<{ $crate::embed::BLOCK }, { $crate::embed::TABLE }>;

        /// Streaming encoder — the `embed` build, compressing blocks of
        /// `BLOCK` bytes, with a hash table of `TABLE` entries to find
        /// matches with. [`Encoder`] is this with the default sizes.
        ///
        /// Matches are only found within a block, so larger blocks compress
        /// better, up to a few times deflate's 32 KiB reach; a larger table
        /// finds more of them. `BLOCK` is 1 to 65536, `TABLE` a power of two
        /// of at most 65536: other values fail to build. The struct takes
        /// `BLOCK + 2 * TABLE` bytes and a few more, and owns everything it
        /// needs; nothing is allocated. `const`-constructible, with an
        /// all-zero state.
        pub struct BlockEncoder<const BLOCK: usize, const TABLE: usize> {
            inner: $crate::embed::encoder::Encoder<$format, BLOCK, TABLE>,
        }

        impl<const BLOCK: usize, const TABLE: usize> BlockEncoder<BLOCK, TABLE> {
            /// Build an encoder.
            pub const fn new() -> Self {
                BlockEncoder {
                    inner: $crate::embed::encoder::Encoder::new(),
                }
            }

            /// Build an encoder with explicit configuration, which has no
            /// effect in `embed` mode: the ratio is set by `BLOCK` and
            /// `TABLE`. Accepted so that code written for the standard build
            /// compiles unchanged.
            pub fn with_config(_: EncoderConfig) -> Self {
                Self::new()
            }
        }

        impl<const BLOCK: usize, const TABLE: usize> Default for BlockEncoder<BLOCK, TABLE> {
            fn default() -> Self {
                Self::new()
            }
        }

        impl<const BLOCK: usize, const TABLE: usize> $crate::traits::RawEncoder
            for BlockEncoder<BLOCK, TABLE>
        {
            fn raw_encode(
                &mut self,
                input: &[u8],
                output: &mut [u8],
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_encode(input, output)
            }
            fn raw_finish(
                &mut self,
                output: &mut [u8],
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_finish(output)
            }
            fn raw_reset(&mut self) {
                self.inner.raw_reset()
            }
            fn raw_flush(
                &mut self,
                output: &mut [u8],
                mode: $crate::traits::Flush,
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_flush(output, mode)
            }
        }

        /// The streaming decoder, with deflate's full
        /// [`WINDOW`](crate::embed::WINDOW): every stream decodes. See
        /// [`WindowedDecoder`] for a smaller one.
        pub type Decoder = WindowedDecoder<{ $crate::embed::WINDOW }>;

        /// Streaming decoder — the `embed` build, with a history window of
        /// `WINDOW` bytes. [`Decoder`] is this with the full 32 KiB.
        ///
        /// `WINDOW` is a power of two of at most 32768: other values fail
        /// to build. The struct takes `WINDOW` bytes and about 1.1 KiB more,
        /// for the codes of the current block. A smaller window only decodes
        /// the streams whose back-references stay within it, such as those
        /// from an encoder whose window is no larger (zlib's `windowBits`,
        /// this crate's [`BlockEncoder`] with a `BLOCK` no larger); a
        /// reference beyond it fails with
        /// [`Error::InvalidDistance`](crate::Error::InvalidDistance).
        ///
        /// Holds its window inline (see [`crate::embed`] for where to put
        /// it); nothing is allocated. `const`-constructible, with an all-zero
        /// state.
        pub struct WindowedDecoder<const WINDOW: usize> {
            inner: $crate::embed::decoder::Decoder<$format, WINDOW>,
        }

        impl<const WINDOW: usize> WindowedDecoder<WINDOW> {
            /// Build a decoder with the default configuration.
            pub const fn new() -> Self {
                WindowedDecoder {
                    inner: $crate::embed::decoder::Decoder::new(),
                }
            }

            /// Build a decoder with the given configuration.
            pub fn with_config(config: DecoderConfig) -> Self {
                let mut decoder = Self::new();
                let window: fn(&DecoderConfig) -> usize = $window;
                decoder.inner.set_window_size(window(&config));
                decoder
            }
        }

        impl<const WINDOW: usize> Default for WindowedDecoder<WINDOW> {
            fn default() -> Self {
                Self::new()
            }
        }

        impl<const WINDOW: usize> $crate::traits::RawDecoder for WindowedDecoder<WINDOW> {
            fn raw_decode(
                &mut self,
                input: &[u8],
                output: &mut [u8],
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_decode(input, output)
            }
            fn raw_finish(
                &mut self,
                output: &mut [u8],
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_finish(output)
            }
            fn raw_reset(&mut self) {
                self.inner.raw_reset()
            }
            fn raw_skip(
                &mut self,
                input: &[u8],
                n: usize,
            ) -> Result<$crate::traits::RawProgress, $crate::error::Error> {
                self.inner.raw_skip(input, n)
            }
        }

        /// Decompresses a whole stream from `input` into `output`, which
        /// doubles as the history window: no state, no window, about 1.3 KiB
        /// of stack. Returns the decompressed length. `embed` build only.
        ///
        /// Fails with
        /// [`Error::OutputTooSmall`](crate::Error::OutputTooSmall) if the
        /// data does not fit, and with
        /// [`Error::UnexpectedEnd`](crate::Error::UnexpectedEnd) if `input`
        /// ends before the stream does. Anything after the stream is
        /// ignored.
        pub fn decompress(input: &[u8], output: &mut [u8]) -> Result<usize, $crate::error::Error> {
            $crate::embed::oneshot::decode::<$format, _>(
                input,
                $crate::embed::oneshot::Buffer::new(output),
            )
        }

        /// Returns the length a stream decompresses to, decoding it in full
        /// but storing nothing: no output, no window, and faster than
        /// [`decompress`]. The data checksum cannot be verified this way;
        /// the structure of the stream, and gzip's recorded length, are.
        /// `embed` build only.
        ///
        /// Fails with
        /// [`Error::OutputLimitExceeded`](crate::Error::OutputLimitExceeded)
        /// once the length exceeds `max_len`, since a few kilobytes of
        /// deflate can stand for gigabytes.
        pub fn decompressed_len(
            input: &[u8],
            max_len: usize,
        ) -> Result<usize, $crate::error::Error> {
            $crate::embed::oneshot::decode::<$format, _>(
                input,
                $crate::embed::oneshot::Counter::new(max_len),
            )
        }

        /// Compresses `input` into `output` as a single deflate block,
        /// finding matches with `table`, of which the largest power of two
        /// of entries, up to 65536, gets used. It need not be cleared, and
        /// an empty one still gets the Huffman coding done. Returns the
        /// compressed length. `embed` build only.
        ///
        /// Matches are found across the whole input, so this compresses at
        /// least as well as a [`BlockEncoder`] with the same table. Fails
        /// with [`Error::OutputTooSmall`](crate::Error::OutputTooSmall) if
        /// the stream does not fit; it is at most an eighth larger than the
        /// input, plus a few bytes.
        pub fn compress(
            input: &[u8],
            table: &mut [u16],
            output: &mut [u8],
        ) -> Result<usize, $crate::error::Error> {
            $crate::embed::encoder::compress::<$format>(input, table, output)
        }
    };
}

#[cfg(feature = "deflate")]
pub(crate) use codec;
