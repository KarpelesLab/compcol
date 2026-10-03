//! The `embed` deflate-family decoder: a push state machine over the
//! primitives in `inflate`, each state a step that reads 32 bits at most.
//!
//! A step runs on whatever input there is. If that runs out midway, the bit
//! reader reads zeros and says so, which guarantees that nothing was output:
//! the step is rolled back, the few bytes it left unread go into the bit
//! buffer, where they fit, and it is taken again when more input comes. If
//! the output runs out instead, the only step that produces more than one
//! byte, copying a match, keeps what is left of it as its next state. So
//! what has to be remembered between calls is the state, the two codes of
//! the current block and the window: nothing depends on how the input or
//! the output is cut.

use super::format::Format;
use super::inflate::{
    Inflate, MAX_LEN_SYMS, MAX_SYMS, ORDER, Symbol, Tables, Window, Windowed, build_codes,
    fixed_lengths,
};
use crate::error::Error;
use crate::traits::{RawDecoder, RawProgress};

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
    /// The header, if the container has one.
    Start,
    /// A gzip member header.
    Member,
    /// So many bytes of gzip header to skip, then the fields these flags
    /// are left of.
    Skip(u16, u16),
    /// The optional fields of a gzip header, a flag for each one left.
    Fields(u16),
    /// A block header.
    Block,
    /// The length of a stored block.
    StoredLen,
    /// So many bytes of a stored block.
    Stored(u16),
    /// The lengths of the code length code of a dynamic block, from this
    /// one.
    CodeLengths(usize),
    /// The code lengths of a dynamic block, from this one.
    Lengths(usize),
    /// A literal/length symbol.
    Length,
    /// The distance of a match of this length.
    Distance(u32),
    /// So many bytes left to copy from so far back.
    Copy(u32, u32),
    /// The checksum of the data.
    Checksum,
    /// The length of the data, after this checksum.
    Size(u32),
    /// Another gzip member, or nothing: decided by the next byte.
    Next,
    Done,
}

/// What is kept from a step to the next, besides the state.
struct Context {
    /// Whether the current block is the last.
    last: bool,
    /// How many literal/length symbols, symbols in all, and code length
    /// symbols the current dynamic block defines.
    len_syms: usize,
    syms: usize,
    code_syms: usize,
    /// Where the output was when the member started, for the gzip length.
    start: u32,
    /// The code lengths of the current block, while they are being read,
    /// then its two codes. The code length code is built in place of the
    /// literal/length one, until that one is.
    lengths: [u8; MAX_SYMS],
    tables: Tables,
}

/// The decoder's view of one call, over a window of `N` bytes.
type Push<'a, F, const N: usize> = Inflate<'a, Windowed<'a, F, N>>;

/// A deflate-family decoder in format `F`, with a window of `N` bytes.
pub(crate) struct Decoder<F, const N: usize> {
    window: Window<N>,
    context: Context,
    format: F,
    state: State,
    bit_buf: u32,
    bit_cnt: u32,
    poisoned: bool,
}

impl<F: Format, const N: usize> Decoder<F, N> {
    pub(crate) const fn new() -> Self {
        Decoder {
            window: Window::new(),
            context: Context {
                last: false,
                len_syms: 0,
                syms: 0,
                code_syms: 0,
                start: 0,
                lengths: [0; MAX_SYMS],
                tables: Tables::new(),
            },
            format: F::INIT,
            state: State::Start,
            bit_buf: 0,
            bit_cnt: 0,
            poisoned: false,
        }
    }

    /// Rejects back-references farther than `window_size` bytes, clamped to
    /// `1..=N`.
    pub(crate) fn set_window_size(&mut self, window_size: usize) {
        self.window.set_max_dist(window_size);
    }

    fn poison(&mut self, error: Error) -> Error {
        self.poisoned = true;
        error
    }

    /// Takes steps until the input, the output or the stream runs out.
    /// Returns how much input was consumed and how much output produced.
    fn run(&mut self, input: &[u8], dst: &mut [u8]) -> Result<(usize, usize), Error> {
        let mut inflate = Inflate {
            input,
            sink: Windowed::new(&mut self.window, &mut self.format, dst),
            bit_buf: self.bit_buf,
            bit_cnt: self.bit_cnt,
            exhausted: false,
        };
        let context = &mut self.context;
        loop {
            match self.state {
                State::Done => break,
                // These produce output, a byte at least; the rest can go on
                // with none.
                State::Stored(1..) | State::Length | State::Copy(..)
                    if inflate.sink.room() == 0 =>
                {
                    break;
                }
                // Another member or not is decided by a byte that is only
                // consumed if it starts one.
                State::Next if F::GZIP => match inflate.input.first() {
                    None => break,
                    Some(0x1f) => self.state = State::Member,
                    Some(_) => self.state = State::Done,
                },
                state => {
                    let saved = (inflate.bit_buf, inflate.bit_cnt, inflate.input);
                    let next = context.step(&mut inflate, state);
                    if inflate.exhausted {
                        // The input ran out: whatever the step made of it is
                        // void. What it left is less than the 32 bits a step
                        // reads at most.
                        inflate.exhausted = false;
                        (inflate.bit_buf, inflate.bit_cnt, inflate.input) = saved;
                        while inflate.bit_cnt <= 24
                            && let Some((&byte, rest)) = inflate.input.split_first()
                        {
                            inflate.bit_buf |= (byte as u32) << inflate.bit_cnt;
                            inflate.bit_cnt += 8;
                            inflate.input = rest;
                        }
                        break;
                    }
                    self.state = next?;
                }
            }
        }
        self.bit_buf = inflate.bit_buf;
        self.bit_cnt = inflate.bit_cnt;
        inflate.sink.flush();
        Ok((input.len() - inflate.input.len(), inflate.sink.len))
    }
}

impl Context {
    /// Takes the step `state` calls for. Returns the state that follows,
    /// which is void, as the rest of what this does, if the input ran out.
    fn step<F: Format, const N: usize>(
        &mut self,
        inflate: &mut Push<'_, F, N>,
        state: State,
    ) -> Result<State, Error> {
        let (mut len_code, mut dist_code) = self.tables.codes();

        // The states of a container other than `F` cannot come up: ruled out
        // by `F`'s constants, their code is left out of the build.
        let gzip = matches!(
            state,
            State::Member | State::Skip(..) | State::Fields(..) | State::Size(..)
        );
        if (gzip && !F::GZIP) || (matches!(state, State::Checksum) && F::TRAILER == 0) {
            return Err(Error::Corrupt);
        }
        Ok(match state {
            State::Start => {
                if F::GZIP {
                    return Ok(State::Member);
                }
                if F::TRAILER == 0 {
                    return Ok(State::Block);
                }
                let cmf = inflate.bits(8);
                let flg = inflate.bits(8);
                if cmf & 0x0f != 8 {
                    return Err(Error::Unsupported);
                }
                if !(cmf * 256 + flg).is_multiple_of(31) {
                    return Err(Error::BadHeader);
                }
                if flg & FDICT != 0 {
                    return Err(Error::Unsupported);
                }
                self.start = inflate.sink.window.written();
                State::Block
            }
            State::Member => {
                // Each member has its own checksum and length.
                *inflate.sink.format = F::INIT;
                self.start = inflate.sink.window.written();
                if inflate.bits(16) != 0x8b1f {
                    return Err(Error::BadHeader);
                }
                if inflate.bits(8) != 8 {
                    return Err(Error::Unsupported);
                }
                let flags = inflate.bits(8);
                if flags & RESERVED != 0 {
                    return Err(Error::Unsupported);
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
                    _ => return Err(Error::InvalidBlockType),
                }
            }
            State::StoredLen => State::Stored(inflate.stored_len()?),
            State::Stored(0) => self.block_end(inflate)?,
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
                            return Err(Error::InvalidHuffmanTree);
                        }
                        State::Lengths(0)
                    }
                }
            }
            State::Lengths(index) => {
                // Literal/length code lengths, directly followed by the
                // distance ones.
                let lengths = self.lengths.get_mut(..self.syms).ok_or(Error::Corrupt)?;
                if index < lengths.len() {
                    State::Lengths(inflate.code_lengths(&len_code, lengths, index)?)
                } else {
                    // A block without an end-of-block code could never finish.
                    if lengths.get(256) == Some(&0) {
                        return Err(Error::InvalidHuffmanTree);
                    }
                    build_codes(lengths, self.len_syms, &mut len_code, &mut dist_code)?;
                    State::Length
                }
            }
            State::Length => match inflate.length(&len_code)? {
                Symbol::Literal => State::Length,
                Symbol::End => self.block_end(inflate)?,
                Symbol::Match(len) => State::Distance(len),
            },
            State::Distance(len) => State::Copy(inflate.distance(&dist_code)?, len),
            State::Copy(dist, len) => match inflate.copy(dist, len)? {
                0 => State::Length,
                left => State::Copy(dist, left),
            },
            State::Checksum => {
                let check = inflate.word();
                if F::GZIP {
                    State::Size(check)
                } else {
                    self.verify(inflate, check, 0)?
                }
            }
            State::Size(check) => {
                let size = inflate.word();
                self.verify(inflate, check, size)?
            }
            // `Next` and `Done` are `run`'s.
            _ => return Err(Error::Corrupt),
        })
    }

    /// Ends a block, and the deflate stream if this was its last, leaving
    /// the input on a byte boundary and the checksum fed everything.
    fn block_end<F: Format, const N: usize>(
        &self,
        inflate: &mut Push<'_, F, N>,
    ) -> Result<State, Error> {
        if !self.last {
            return Ok(State::Block);
        }
        inflate.align();
        inflate.sink.flush();
        Ok(match F::TRAILER {
            0 => State::Done,
            _ => State::Checksum,
        })
    }

    /// Checks the trailer of a stream against its data: the checksum, and
    /// for gzip the length. Returns what comes after the stream.
    fn verify<F: Format, const N: usize>(
        &self,
        inflate: &mut Push<'_, F, N>,
        check: u32,
        size: u32,
    ) -> Result<State, Error> {
        let written = inflate.sink.window.written().wrapping_sub(self.start);
        let [expected, _] = inflate.sink.format.trailer(written);
        if check != expected {
            return Err(Error::ChecksumMismatch);
        }
        if F::GZIP && size != written {
            return Err(Error::TrailerMismatch);
        }
        Ok(match F::GZIP {
            true => State::Next,
            false => State::Done,
        })
    }
}

impl<F: Format, const N: usize> RawDecoder for Decoder<F, N> {
    fn raw_decode(&mut self, input: &[u8], output: &mut [u8]) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        let (consumed, written) = self.run(input, output).map_err(|e| self.poison(e))?;
        Ok(RawProgress {
            consumed,
            written,
            done: matches!(self.state, State::Done),
        })
    }

    fn raw_finish(&mut self, output: &mut [u8]) -> Result<RawProgress, Error> {
        let p = self.raw_decode(&[], output)?;
        match self.state {
            // Nothing after the last gzip member: that was the stream.
            State::Done | State::Next => {
                self.state = State::Done;
                Ok(RawProgress { done: true, ..p })
            }
            // A match still being copied, for want of output: the bridge
            // has the caller come back with another buffer.
            _ if p.written == output.len() && !output.is_empty() => Ok(p),
            _ => Err(self.poison(Error::UnexpectedEnd)),
        }
    }

    fn raw_reset(&mut self) {
        self.window.reset();
        self.format = F::INIT;
        self.state = State::Start;
        self.bit_buf = 0;
        self.bit_cnt = 0;
        self.poisoned = false;
    }

    fn raw_skip(&mut self, input: &[u8], n: usize) -> Result<RawProgress, Error> {
        if self.poisoned {
            return Err(Error::Corrupt);
        }
        // Decoded through a scrap of stack, so that decoding proper never
        // has to tell where its output goes.
        let mut scrap = [0; 64];
        let (mut consumed, mut written) = (0, 0);
        while written < n {
            let want = (n - written).min(scrap.len());
            let rest = input.get(consumed..).unwrap_or(&[]);
            let dst = scrap.get_mut(..want).unwrap_or(&mut []);
            let (c, w) = self.run(rest, dst).map_err(|e| self.poison(e))?;
            consumed += c;
            written += w;
            if w < want {
                break;
            }
        }
        Ok(RawProgress {
            consumed,
            written,
            done: matches!(self.state, State::Done),
        })
    }
}
