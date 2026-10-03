//! The push decoder: the input comes when it comes, in pieces of any size.
//!
//! The pull decoder keeps its state on the stack, and cannot return for want
//! of input. This one is its loops unrolled into a state machine, each state a
//! step that reads 32 bits at most, over the same primitives. A step is run on
//! whatever input there is. If that runs out midway, the bit reader reads
//! zeros and says so, as it does for the pull decoder, which guarantees that
//! nothing was output: the step is rolled back, the few bytes it left unread
//! go into the bit buffer, where they fit, and it is taken again when more
//! input comes. All a step changes besides is either part of the state, or
//! written again from scratch when the step is retried.

use super::inflate::Inflate;
use super::inflate::ORDER;
use super::inflate::{MAX_LEN_SYMS, fixed_lengths};
use super::inflate::{MAX_SYMS, Symbol, Tables, build_codes};
use super::{Checksum, Container, Error, Output};

// Gzip header flags.
const FHCRC: u16 = 1 << 1;
const FEXTRA: u16 = 1 << 2;
const FNAME: u16 = 1 << 3;
const FCOMMENT: u16 = 1 << 4;
const RESERVED: u16 = 0xe0;
// Zlib header flag.
const FDICT: u16 = 1 << 5;

/// What comes next in the stream.
#[derive(Clone, Copy)]
enum State {
    /// The first byte of a header, if the container has one.
    Start,
    /// A gzip header, past its first byte.
    Member,
    /// So many bytes of gzip header to skip, then the fields these flags are
    /// left of.
    Skip(u16, u16),
    /// The optional fields of a gzip header, a flag for each one left.
    Fields(u16),
    /// A block header.
    Block,
    /// The length of a stored block.
    StoredLen,
    /// So many bytes of a stored block.
    Stored(u16),
    /// The lengths of the code length code of a dynamic block, from this one.
    CodeLengths(usize),
    /// The code lengths of a dynamic block, from this one.
    Lengths(usize),
    /// A literal/length symbol.
    Length,
    /// The distance of a match of this length.
    Distance(u32),
    /// The checksum of the data.
    Checksum,
    /// The length of the data, after this checksum.
    Size(u32),
    /// Another gzip member, or nothing.
    Next,
    Done,
    Failed(Error),
}

/// Feeds the container's checksum, if checksums are verified at all.
struct Check<'a, F>(&'a mut F);

impl<F: Container> Checksum for Check<'_, F> {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

/// What is kept from a step to the next, besides the state. It is aligned,
/// and has no 64-bit field, so that clearing it is a job for `memclr4`, which
/// is linked anyway, rather than for another routine of `compiler_builtins`.
#[repr(align(4))]
struct Context {
    bit_buf: u32,
    bit_cnt: u32,
    /// Whether this is a gzip stream, and where the output was when its
    /// current member started, modulo 2<sup>32</sup> as the length it records.
    gzip: bool,
    start: u32,
    /// Whether the current block is the last.
    last: bool,
    /// How many literal/length symbols, symbols in all, and code length
    /// symbols the current dynamic block defines.
    len_syms: usize,
    syms: usize,
    code_syms: usize,
    /// The code lengths of the current block, while they are being read, then
    /// its two codes. The code length code is built in place of the
    /// literal/length one, until that one is.
    lengths: [u8; MAX_SYMS],
    tables: Tables,
}

/// Stream in, pushed: decompresses format `F` from whatever input comes, in
/// pieces of any size, a byte at a time if need be.
///
/// Where the functions, such as [`gunzip`](fn.gunzip.html), pull their input
/// and only return once done, this is for when the input is not yours to ask
/// for: [`write`](Self::write) what arrives, as it arrives, then
/// [`finish`](Self::finish). `F` is [`Gzip`](struct.Gzip.html),
/// [`Zlib`](struct.Zlib.html), [`Raw`](super::Raw), or
/// [`Detect`](struct.Detect.html) for either of the first two.
///
/// The decompressed data goes to any [`Output`]. Whatever can be decoded from
/// the input so far is, and is delivered before `write` returns: a
/// [`Stream`](super::Stream) gets its callback invoked for it then, without
/// waiting for its window to fill up.
///
/// What has to be remembered from one piece of input to the next, the codes
/// of the current block mostly, is kept in here: about 1.1 KiB, in place of
/// the stack the functions use, and nothing depends on the size of the pieces.
pub struct Decompressor<O, F> {
    out: O,
    format: F,
    state: State,
    /// Where the output was when the stream started.
    begin: u64,
    context: Context,
}

impl<O: Output, F: Container> Decompressor<O, F> {
    /// Starts decompressing a stream.
    ///
    /// The decompressor is built in place: handing it over inside a `Result`
    /// would have it copied, and drag `memcpy` in.
    #[inline(always)]
    pub fn new(output: O) -> Self {
        Decompressor {
            begin: output.written(),
            out: output,
            format: F::new(),
            state: State::Start,
            context: Context {
                bit_buf: 0,
                bit_cnt: 0,
                gzip: false,
                start: 0,
                last: false,
                len_syms: 0,
                syms: 0,
                code_syms: 0,
                lengths: [0; MAX_SYMS],
                tables: Tables::new(),
            },
        }
    }

    /// Decompresses the next piece of the stream, of any length, as far as it
    /// goes. Returns how much of `data` was consumed: all of it, unless the
    /// stream ended before it did.
    ///
    /// No more than the stream is consumed, apart from the single look-ahead
    /// byte needed to detect another gzip member. Once an error is returned,
    /// it is all that is ever returned.
    pub fn write(&mut self, data: &[u8]) -> Result<usize, Error> {
        let mut input = data;
        match self.run(&mut input) {
            Ok(()) => Ok(data.len() - input.len()),
            Err(error) => {
                self.state = State::Failed(error);
                Err(error)
            }
        }
    }

    /// Whether the stream has ended, and `write` has nothing left to consume.
    ///
    /// A gzip stream only ends for sure with something other than a gzip
    /// member, or with `finish`.
    pub fn is_done(&self) -> bool {
        matches!(self.state, State::Done)
    }

    /// Ends the input, which fails with [`Error::UnexpectedEof`] unless the
    /// stream has ended as well. Returns the number of bytes produced.
    ///
    /// The decompressor is then ready for another stream, to the same output.
    /// This takes no `self`: that would be a copy, and drag `memcpy` in.
    pub fn finish(&mut self) -> Result<u64, Error> {
        let state = core::mem::replace(&mut self.state, State::Start);
        let end = self.out.written();
        let len = end - self.begin;
        self.begin = end;
        self.format = F::new();
        self.context.bit_buf = 0;
        self.context.bit_cnt = 0;
        match state {
            State::Done | State::Next => Ok(len),
            State::Failed(error) => Err(error),
            _ => Err(Error::UnexpectedEof),
        }
    }

    /// Takes steps until the input or the stream runs out.
    fn run(&mut self, input: &mut &[u8]) -> Result<(), Error> {
        let context = &mut self.context;
        let mut inflate = Inflate {
            input,
            out: &mut self.out,
            check: Check(&mut self.format),
            bit_buf: context.bit_buf,
            bit_cnt: context.bit_cnt,
            status: Ok(()),
        };
        while !matches!(self.state, State::Done) {
            let saved = (inflate.bit_buf, inflate.bit_cnt, *inflate.input);
            let next = context.step(&mut inflate, self.state);
            if inflate.status.is_err() {
                // The input ran out: whatever the step made of it is void.
                // What it left is less than the 32 bits a step reads at most.
                inflate.status = Ok(());
                (inflate.bit_buf, inflate.bit_cnt, *inflate.input) = saved;
                while inflate.bit_cnt <= 24
                    && let Some((&byte, rest)) = inflate.input.split_first()
                {
                    inflate.bit_buf |= (byte as u32) << inflate.bit_cnt;
                    inflate.bit_cnt += 8;
                    *inflate.input = rest;
                }
                break;
            }
            self.state = next?;
        }
        context.bit_buf = inflate.bit_buf;
        context.bit_cnt = inflate.bit_cnt;
        inflate.out.flush(&mut inflate.check)
    }
}

impl Context {
    /// Takes the step `state` calls for. Returns the state that follows, which
    /// is void, as the rest of what this does, if the input ran out.
    fn step<O: Output, F: Container>(
        &mut self,
        inflate: &mut Inflate<'_, &[u8], O, Check<'_, F>>,
        state: State,
    ) -> Result<State, Error> {
        let (mut len_code, mut dist_code) = self.tables.codes();

        Ok(match state {
            State::Start => {
                if F::TRAILER == 0 {
                    return Ok(State::Block);
                }
                let first = inflate.bits(8) as u8;
                if inflate.check.0.detect(first) {
                    if first != 0x1f {
                        return Err(Error::InvalidHeader);
                    }
                    return Ok(State::Member);
                }
                let flags = inflate.bits(8);
                if !(first as u16 * 256 + flags).is_multiple_of(31) {
                    return Err(Error::InvalidHeader);
                }
                // Deflate with a window of at most 32 KiB, and no preset
                // dictionary.
                if first & 0x0f != 8 || first >> 4 > 7 || flags & FDICT != 0 {
                    return Err(Error::Unsupported);
                }
                self.gzip = false;
                State::Block
            }
            State::Member => {
                // Each member has its own checksum and length.
                *inflate.check.0 = F::new();
                inflate.check.0.detect(0x1f);
                self.gzip = true;
                self.start = inflate.out.written() as u32;
                // ID2 and CM.
                match inflate.bits(16) {
                    0x088b => {}
                    other if other as u8 == 0x8b => return Err(Error::Unsupported),
                    _ => return Err(Error::InvalidHeader),
                }
                let flags = inflate.bits(8);
                if flags & RESERVED != 0 {
                    return Err(Error::InvalidHeader);
                }
                // MTIME, XFL and OS.
                State::Skip(6, flags)
            }
            State::Skip(0, flags) => State::Fields(flags),
            State::Skip(bytes, flags) => {
                inflate.bits(8);
                State::Skip(bytes - 1, flags)
            }
            State::Fields(flags) => {
                let text = flags & (FNAME | FCOMMENT);
                if flags & FEXTRA != 0 {
                    State::Skip(inflate.bits(16), flags & !FEXTRA)
                } else if text != 0 {
                    // The name then the comment, a byte at a time up to a
                    // zero, which clears the lowest of their flags.
                    match inflate.bits(8) {
                        0 => State::Fields(flags & !(text & text.wrapping_neg())),
                        _ => State::Fields(flags),
                    }
                } else if flags & FHCRC != 0 {
                    // The header CRC is not verified: gzip never writes one.
                    State::Skip(2, flags & !FHCRC)
                } else {
                    State::Block
                }
            }
            State::Block => {
                self.last = inflate.bits(1) != 0;
                match inflate.bits(2) {
                    0 => {
                        inflate.align();
                        State::StoredLen
                    }
                    1 => {
                        fixed_lengths(&mut self.lengths);
                        build_codes(&self.lengths, MAX_LEN_SYMS, &mut len_code, &mut dist_code)?;
                        State::Length
                    }
                    2 => {
                        let (len_syms, dist_syms, code_syms) = inflate.dynamic_head()?;
                        self.len_syms = len_syms;
                        self.syms = len_syms + dist_syms;
                        self.code_syms = code_syms;
                        // The code lengths that are not given are zeros.
                        if let Some(head) = self.lengths.first_chunk_mut::<19>() {
                            *head = [0; 19];
                        }
                        State::CodeLengths(0)
                    }
                    3 => return Err(Error::InvalidBlock),
                    _ => return Err(Error::Unsupported),
                }
            }
            State::StoredLen => State::Stored(inflate.stored_len()?),
            State::Stored(0) => block_end(inflate, self.last)?,
            State::Stored(bytes) => {
                inflate.stored_byte()?;
                State::Stored(bytes - 1)
            }
            State::CodeLengths(index) => {
                match ORDER.get(index).filter(|_| index < self.code_syms) {
                    Some(&sym) => {
                        self.lengths[(sym & 31) as usize] = inflate.bits(3) as u8;
                        State::CodeLengths(index + 1)
                    }
                    None => {
                        len_code.build(&self.lengths[..19]);
                        if len_code.left != 0 {
                            return Err(Error::InvalidCode);
                        }
                        State::Lengths(0)
                    }
                }
            }
            State::Lengths(index) => {
                // Literal/length code lengths, directly followed by the
                // distance ones.
                let lengths = self
                    .lengths
                    .get_mut(..self.syms)
                    .ok_or(Error::InvalidBlock)?;
                if index < lengths.len() {
                    State::Lengths(inflate.code_lengths(&len_code, lengths, index)?)
                } else {
                    // A block without an end-of-block code could never finish.
                    if lengths.get(256) == Some(&0)
                        || !build_codes(lengths, self.len_syms, &mut len_code, &mut dist_code)?
                    {
                        return Err(Error::InvalidCode);
                    }
                    State::Length
                }
            }
            State::Length => match inflate.length(&len_code)? {
                Symbol::Literal => State::Length,
                Symbol::End => block_end(inflate, self.last)?,
                Symbol::Match(len) => State::Distance(len),
            },
            State::Distance(len) => {
                inflate.distance(&dist_code, len)?;
                State::Length
            }
            State::Checksum => {
                let low = inflate.bits(16) as u32;
                let check = (inflate.bits(16) as u32) << 16 | low;
                match self.gzip {
                    true => State::Size(check),
                    false => self.verify(inflate, check, 0)?,
                }
            }
            State::Size(check) => {
                let low = inflate.bits(16) as u32;
                let size = (inflate.bits(16) as u32) << 16 | low;
                self.verify(inflate, check, size)?
            }
            // Another member may follow. Anything else is ignored, as gzip
            // does with trailing padding.
            State::Next => match inflate.bits(8) {
                0x1f => State::Member,
                _ => State::Done,
            },
            State::Done => State::Done,
            State::Failed(error) => return Err(error),
        })
    }
}

impl Context {
    /// Checks the trailer of a stream against its data: the checksum, which
    /// takes an output that keeps the data, and for gzip the length, which
    /// any output can tell. Returns what comes after the stream.
    fn verify<O: Output, F: Container>(
        &self,
        inflate: &mut Inflate<'_, &[u8], O, Check<'_, F>>,
        check: u32,
        size: u32,
    ) -> Result<State, Error> {
        let written = (inflate.out.written() as u32).wrapping_sub(self.start);
        let [expected, _] = inflate.check.0.trailer(written);
        if (O::VERIFY && check != expected) || (self.gzip && size != written) {
            return Err(Error::ChecksumMismatch);
        }
        Ok(match self.gzip {
            true => State::Next,
            false => State::Done,
        })
    }
}

/// Ends a block, and the deflate stream if this was its last, leaving the
/// input on a byte boundary and the output flushed for its checksum.
fn block_end<O: Output, F: Container>(
    inflate: &mut Inflate<'_, &[u8], O, Check<'_, F>>,
    last: bool,
) -> Result<State, Error> {
    if !last {
        return Ok(State::Block);
    }
    inflate.align();
    inflate.out.flush(&mut inflate.check)?;
    Ok(match F::TRAILER {
        0 => State::Done,
        _ => State::Checksum,
    })
}
