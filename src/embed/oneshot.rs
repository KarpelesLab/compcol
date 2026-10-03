//! The one-shot `embed` decoder: a whole stream from one slice into another,
//! or only its length, with no window and no state kept.
//!
//! The output slice is the history window, so nothing else is needed but the
//! stack: the two codes of the current block and the code lengths they are
//! built from, about 1.3 KiB, for the length of the call. The loops are the
//! push decoder's steps, run back to back. When the input runs out, the bit
//! reader reads zeros, which end every loop that could otherwise go on, and
//! the end of the input is reported rather than whatever the zeros made.

use super::format::Format;
use super::inflate::{
    Counts, Huffman, Inflate, MAX_BITS, MAX_LEN_SYMS, MAX_SYMS, ORDER, Out, Symbol, Tables,
    build_codes, fixed_lengths,
};
use crate::error::Error;

// Gzip header flags.
const FHCRC: u16 = 1 << 1;
const FEXTRA: u16 = 1 << 2;
const FNAME: u16 = 1 << 3;
const FCOMMENT: u16 = 1 << 4;
const RESERVED: u16 = 0xe0;
// Zlib header flag.
const FDICT: u16 = 1 << 5;

/// Where a one-shot decode puts its output, which back-references are
/// copied from.
pub(crate) trait Output: Out {
    /// Whether the data is kept, so that its checksum can be verified.
    const VERIFY: bool;
    /// Bytes produced so far.
    fn written(&self) -> usize;
    /// The data produced from `start` on, if it is kept.
    fn data(&self, start: usize) -> &[u8];
    /// Appends `len` bytes copied from `dist` bytes back.
    fn copy(&mut self, dist: u32, len: u32) -> Result<(), Error>;
}

/// Decompresses into a slice, which doubles as the history window. Fails
/// with `Error::OutputTooSmall` if the data does not fit.
pub(crate) struct Buffer<'a> {
    buf: &'a mut [u8],
    pos: usize,
}

impl<'a> Buffer<'a> {
    pub(crate) fn new(buf: &'a mut [u8]) -> Self {
        Buffer { buf, pos: 0 }
    }
}

impl Out for Buffer<'_> {
    #[inline]
    fn put(&mut self, byte: u8) -> Result<(), Error> {
        *self.buf.get_mut(self.pos).ok_or(Error::OutputTooSmall)? = byte;
        self.pos += 1;
        Ok(())
    }

    /// Checked by `copy`, which has to anyway.
    #[inline(always)]
    fn check_dist(&self, _: u32) -> Result<(), Error> {
        Ok(())
    }
}

impl Output for Buffer<'_> {
    const VERIFY: bool = true;

    fn written(&self) -> usize {
        self.pos
    }

    fn data(&self, start: usize) -> &[u8] {
        self.buf.get(start..self.pos).unwrap_or(&[])
    }

    fn copy(&mut self, dist: u32, len: u32) -> Result<(), Error> {
        let start = self
            .pos
            .checked_sub(dist as usize)
            .ok_or(Error::InvalidDistance)?;
        // Should this wrap around, the range is invalid and gets refused.
        let end = self.pos.wrapping_add(len as usize);
        let region = self.buf.get_mut(start..end).ok_or(Error::OutputTooSmall)?;
        // The ranges overlap when `len > dist`, which repeats the last `dist`
        // bytes, so a byte at a time.
        for i in dist as usize..region.len() {
            region[i] = region[i - dist as usize];
        }
        self.pos = end;
        Ok(())
    }
}

/// Discards the data and only counts it: a back-reference has a known
/// length whatever it points at. Fails with `Error::OutputLimitExceeded`
/// past `max`.
pub(crate) struct Counter {
    count: usize,
    max: usize,
}

impl Counter {
    pub(crate) fn new(max: usize) -> Self {
        Counter { count: 0, max }
    }
}

impl Out for Counter {
    #[inline]
    fn put(&mut self, _: u8) -> Result<(), Error> {
        self.copy(0, 1)
    }

    #[inline(always)]
    fn check_dist(&self, _: u32) -> Result<(), Error> {
        Ok(())
    }
}

impl Output for Counter {
    const VERIFY: bool = false;

    fn written(&self) -> usize {
        self.count
    }

    fn data(&self, _: usize) -> &[u8] {
        &[]
    }

    fn copy(&mut self, dist: u32, len: u32) -> Result<(), Error> {
        if dist as usize > self.count {
            return Err(Error::InvalidDistance);
        }
        // `count` never exceeds `max`, so this cannot overflow.
        if len as usize > self.max - self.count {
            return Err(Error::OutputLimitExceeded);
        }
        self.count += len as usize;
        Ok(())
    }
}

/// Decodes a whole stream in format `F` from `input` into `out`. Returns the
/// number of bytes produced.
pub(crate) fn decode<F: Format, O: Output>(input: &[u8], out: O) -> Result<usize, Error> {
    let mut inflate = Inflate {
        input,
        sink: out,
        bit_buf: 0,
        bit_cnt: 0,
        exhausted: false,
    };
    let result = container::<F, O>(&mut inflate);
    // Whatever the zeros read past the end made, the end is what went wrong.
    inflate.ready()?;
    result?;
    Ok(inflate.sink.written())
}

fn container<F: Format, O: Output>(inflate: &mut Inflate<'_, O>) -> Result<(), Error> {
    if F::GZIP {
        // Each member in turn, as long as another one starts. Members end on
        // a byte boundary with nothing left in the bit buffer, so the next
        // byte can be looked at without being consumed.
        loop {
            member::<F, O>(inflate)?;
            if inflate.input.first() != Some(&0x1f) {
                return Ok(());
            }
        }
    }
    if F::TRAILER == 0 {
        return blocks(inflate);
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
    blocks(inflate)?;
    let check = inflate.word();
    verify::<F, O>(inflate, 0, check)
}

/// Decodes one gzip member.
fn member<F: Format, O: Output>(inflate: &mut Inflate<'_, O>) -> Result<(), Error> {
    let start = inflate.sink.written();
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
    // MTIME, XFL and OS, then the extra field.
    skip(inflate, 6);
    if flags & FEXTRA != 0 {
        let len = inflate.bits(16);
        skip(inflate, len);
    }
    for field in [FNAME, FCOMMENT] {
        if flags & field != 0 {
            // Zeros, once the input is out, end this.
            while inflate.bits(8) != 0 {}
        }
    }
    if flags & FHCRC != 0 {
        // The header CRC is not verified: gzip never writes one.
        skip(inflate, 2);
    }

    blocks(inflate)?;
    let check = inflate.word();
    let size = inflate.word();
    verify::<F, O>(inflate, start, check)?;
    if size != (inflate.sink.written() - start) as u32 {
        return Err(Error::TrailerMismatch);
    }
    Ok(())
}

fn skip<O: Out>(inflate: &mut Inflate<'_, O>, bytes: u16) {
    for _ in 0..bytes {
        inflate.bits(8);
    }
}

/// Checks the checksum of what was produced from `start` on, if it was kept.
fn verify<F: Format, O: Output>(
    inflate: &Inflate<'_, O>,
    start: usize,
    check: u32,
) -> Result<(), Error> {
    if O::VERIFY {
        let mut format = F::INIT;
        format.update(inflate.sink.data(start));
        let [expected, _] = format.trailer(0);
        if check != expected {
            return Err(Error::ChecksumMismatch);
        }
    }
    Ok(())
}

/// Decodes the blocks of a deflate stream, leaving the input on a byte
/// boundary after the last.
fn blocks<O: Output>(inflate: &mut Inflate<'_, O>) -> Result<(), Error> {
    loop {
        let last = inflate.bits(1) != 0;
        match inflate.bits(2) {
            0 => {
                for _ in 0..inflate.stored_len()? {
                    inflate.stored_byte()?;
                }
            }
            1 => {
                let mut lengths = [0; MAX_SYMS];
                fixed_lengths(&mut lengths);
                compressed(inflate, &lengths, MAX_LEN_SYMS)?;
            }
            2 => dynamic(inflate)?,
            _ => return Err(Error::InvalidBlockType),
        }
        if last {
            inflate.align();
            return Ok(());
        }
    }
}

fn dynamic<O: Output>(inflate: &mut Inflate<'_, O>) -> Result<(), Error> {
    let (len_syms, dist_syms, code_syms) = inflate.dynamic_head()?;

    let mut lengths = [0u8; MAX_SYMS];
    for &sym in ORDER.iter().take(code_syms) {
        lengths[(sym & 31) as usize] = inflate.bits(3) as u8;
    }
    let mut count = Counts([0; MAX_BITS + 1]);
    let mut symbol = [0; 19];
    let mut code = Huffman::new(&mut count, &mut symbol);
    code.build(&lengths[..19]);
    if code.left != 0 {
        return Err(Error::InvalidHuffmanTree);
    }

    // Literal/length code lengths, directly followed by the distance ones.
    let lengths = lengths
        .get_mut(..len_syms + dist_syms)
        .ok_or(Error::Corrupt)?;
    let mut index = 0;
    while index < lengths.len() {
        index = inflate.code_lengths(&code, lengths, index)?;
    }
    // A block without an end-of-block code could never finish.
    if lengths.get(256) == Some(&0) {
        return Err(Error::InvalidHuffmanTree);
    }
    compressed(inflate, lengths, len_syms)
}

/// Decodes a compressed block given the code length of each literal/length
/// symbol, directly followed by those of the distance symbols.
fn compressed<O: Output>(
    inflate: &mut Inflate<'_, O>,
    lengths: &[u8],
    len_syms: usize,
) -> Result<(), Error> {
    let mut tables = Tables::new();
    let (mut len_code, mut dist_code) = tables.codes();
    build_codes(lengths, len_syms, &mut len_code, &mut dist_code)?;
    loop {
        match inflate.length(&len_code)? {
            Symbol::Literal => {}
            Symbol::End => return Ok(()),
            Symbol::Match(len) => {
                let dist = inflate.distance(&dist_code)?;
                inflate.sink.copy(dist, len)?;
            }
        }
    }
}
