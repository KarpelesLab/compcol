//! The gzip (RFC 1952) and zlib (RFC 1950) containers.
//!
//! Headers and trailers are read through the decoder's bit reader, sixteen
//! bits at most at a time: one primitive serves everything, and its result
//! fits in a register.

#[cfg(feature = "zlib")]
use super::checksum::Adler32;
#[cfg(feature = "gzip")]
use super::checksum::Crc32;
use super::inflate::Inflate;
use super::{Error, Input, Output};

/// Decodes a gzip stream whose first byte, `first`, was already read.
#[cfg(feature = "gzip")]
pub(crate) fn gzip<I: Input, O: Output>(
    first: u8,
    input: &mut I,
    out: &mut O,
) -> Result<(), Error> {
    if first != 0x1f {
        return Err(Error::InvalidHeader);
    }
    member(input, out)?;
    // Another member may follow. Anything else is ignored, as gzip does with
    // trailing padding.
    loop {
        match input.byte() {
            Ok(0x1f) => member(input, out)?,
            Ok(_) | Err(Error::UnexpectedEof) => break,
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

/// Decodes one gzip member, past the first byte of its header.
#[cfg(feature = "gzip")]
fn member<I: Input, O: Output>(input: &mut I, out: &mut O) -> Result<(), Error> {
    const FHCRC: u16 = 1 << 1;
    const FEXTRA: u16 = 1 << 2;
    const FNAME: u16 = 1 << 3;
    const FCOMMENT: u16 = 1 << 4;
    const RESERVED: u16 = 0xe0;

    let (check, start) = (Crc32::new(), out.written());
    Inflate::new(input, out, check).run(|state| {
        // ID2 and CM.
        match state.bits(16) {
            0x088b => {}
            other if other as u8 == 0x8b => return Err(Error::Unsupported),
            _ => return Err(Error::InvalidHeader),
        }
        let flags = state.bits(8);
        if flags & RESERVED != 0 {
            return Err(Error::InvalidHeader);
        }
        // MTIME, XFL and OS, then the extra field.
        state.skip(6);
        if flags & FEXTRA != 0 {
            let len = state.bits(16);
            state.skip(len);
        }
        for field in [FNAME, FCOMMENT] {
            if flags & field != 0 {
                while state.bits(8) != 0 {}
            }
        }
        if flags & FHCRC != 0 {
            // The header CRC is not verified: gzip never writes one.
            state.skip(2);
        }

        state.inflate()?;

        // CRC-32 and ISIZE, as four little-endian halves.
        let mut trailer = [0; 4];
        for half in &mut trailer {
            *half = state.bits(16);
        }
        {
            let [crc_low, crc_high, size_low, size_high] = trailer.map(u32::from);
            let size = (state.out.written() - start) as u32;
            if (O::VERIFY && crc_high << 16 | crc_low != state.check.value())
                || size_high << 16 | size_low != size
            {
                return Err(Error::ChecksumMismatch);
            }
        }
        Ok(())
    })
}

/// Decodes a zlib stream whose first byte, `first`, was already read.
#[cfg(feature = "zlib")]
pub(crate) fn zlib<I: Input, O: Output>(
    first: u8,
    input: &mut I,
    out: &mut O,
) -> Result<(), Error> {
    const FDICT: u16 = 1 << 5;

    let check = Adler32::new();
    Inflate::new(input, out, check).run(|state| {
        let flags = state.bits(8);
        if !(first as u16 * 256 + flags).is_multiple_of(31) {
            return Err(Error::InvalidHeader);
        }
        // Deflate with a window of at most 32 KiB, and no preset dictionary.
        if first & 0x0f != 8 || first >> 4 > 7 || flags & FDICT != 0 {
            return Err(Error::Unsupported);
        }

        state.inflate()?;

        // Adler-32, as two big-endian halves.
        let high = state.bits(16).swap_bytes();
        let low = state.bits(16).swap_bytes();
        if O::VERIFY && (high as u32) << 16 | low as u32 != state.check.value() {
            return Err(Error::ChecksumMismatch);
        }
        Ok(())
    })
}
