//! A bare-metal program around one `embed` codec: `entry` runs it over
//! caller-supplied buffers, the codec itself living in a `static` as it
//! would in firmware. Built by `check.sh` for a Cortex-M target and
//! measured; never run.

#![no_std]
#![no_main]

#[allow(unused_imports)]
use compcol::{Decoder, Encoder, Status};

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// Runs a decoder to the end of its stream. Returns the decoded length, or
/// -1 on error, -2 if `dst` is too small.
#[allow(dead_code)]
fn decode<D: Decoder>(dec: &mut D, src: &[u8], dst: &mut [u8]) -> isize {
    let mut consumed = 0;
    let mut written = 0;
    loop {
        let input = src.get(consumed..).unwrap_or(&[]);
        let output = dst.get_mut(written..).unwrap_or(&mut []);
        let Ok((p, status)) = dec.decode(input, output) else {
            return -1;
        };
        consumed += p.consumed;
        written += p.written;
        match status {
            Status::StreamEnd => return written as isize,
            Status::OutputFull if written >= dst.len() => return -2,
            Status::InputEmpty if consumed >= src.len() => {
                let output = dst.get_mut(written..).unwrap_or(&mut []);
                return match dec.finish(output) {
                    Ok((p, Status::StreamEnd)) => (written + p.written) as isize,
                    _ => -1,
                };
            }
            _ => {}
        }
    }
}

/// Runs an encoder over `src`. Returns the encoded length, or -1 on error,
/// -2 if `dst` is too small.
#[allow(dead_code)]
fn encode<E: Encoder>(enc: &mut E, src: &[u8], dst: &mut [u8]) -> isize {
    let mut consumed = 0;
    let mut written = 0;
    while consumed < src.len() {
        let input = src.get(consumed..).unwrap_or(&[]);
        let output = dst.get_mut(written..).unwrap_or(&mut []);
        let Ok((p, status)) = enc.encode(input, output) else {
            return -1;
        };
        consumed += p.consumed;
        written += p.written;
        if matches!(status, Status::OutputFull) && p.written == 0 && p.consumed == 0 {
            return -2;
        }
    }
    loop {
        let output = dst.get_mut(written..).unwrap_or(&mut []);
        let Ok((p, status)) = enc.finish(output) else {
            return -1;
        };
        written += p.written;
        match status {
            Status::StreamEnd => return written as isize,
            _ if p.written == 0 => return -2,
            _ => {}
        }
    }
}

macro_rules! decoder_entry {
    ($feature:literal, $module:ident) => {
        decoder_entry!($feature, compcol::$module::Decoder);
    };
    ($feature:literal, $decoder:ty) => {
        #[cfg(feature = $feature)]
        static mut DECODER: $decoder = <$decoder>::new();

        #[cfg(feature = $feature)]
        #[unsafe(no_mangle)]
        pub extern "C" fn entry(
            src: *const u8,
            src_len: usize,
            dst: *mut u8,
            dst_len: usize,
        ) -> isize {
            let src = unsafe { core::slice::from_raw_parts(src, src_len) };
            let dst = unsafe { core::slice::from_raw_parts_mut(dst, dst_len) };
            let dec = unsafe { &mut *core::ptr::addr_of_mut!(DECODER) };
            dec.reset();
            decode(dec, src, dst)
        }
    };
}

macro_rules! encoder_entry {
    ($feature:literal, $module:ident) => {
        encoder_entry!($feature, compcol::$module::Encoder);
    };
    ($feature:literal, $encoder:ty) => {
        #[cfg(feature = $feature)]
        static mut ENCODER: $encoder = <$encoder>::new();

        #[cfg(feature = $feature)]
        #[unsafe(no_mangle)]
        pub extern "C" fn entry(
            src: *const u8,
            src_len: usize,
            dst: *mut u8,
            dst_len: usize,
        ) -> isize {
            let src = unsafe { core::slice::from_raw_parts(src, src_len) };
            let dst = unsafe { core::slice::from_raw_parts_mut(dst, dst_len) };
            let enc = unsafe { &mut *core::ptr::addr_of_mut!(ENCODER) };
            enc.reset();
            encode(enc, src, dst)
        }
    };
}

decoder_entry!("gzip-decode", gzip);
decoder_entry!("zlib-decode", zlib);
decoder_entry!("deflate-decode", deflate);
encoder_entry!("gzip-encode", gzip);
encoder_entry!("zlib-encode", zlib);
encoder_entry!("deflate-encode", deflate);
// The same codecs with smaller sizes picked at build time.
decoder_entry!("gzip-decode-4k", compcol::gzip::WindowedDecoder<4096>);
encoder_entry!("gzip-encode-small", compcol::gzip::BlockEncoder<1024, 256>);

/// The one-shot decoders: slice to slice, no state, the output as window.
macro_rules! decompress_entry {
    ($feature:literal, $module:ident) => {
        #[cfg(feature = $feature)]
        #[unsafe(no_mangle)]
        pub extern "C" fn entry(
            src: *const u8,
            src_len: usize,
            dst: *mut u8,
            dst_len: usize,
        ) -> isize {
            let src = unsafe { core::slice::from_raw_parts(src, src_len) };
            let dst = unsafe { core::slice::from_raw_parts_mut(dst, dst_len) };
            compcol::$module::decompress(src, dst).map_or(-1, |len| len as isize)
        }
    };
}

decompress_entry!("gzip-decompress", gzip);
decompress_entry!("zlib-decompress", zlib);
decompress_entry!("deflate-decompress", deflate);

/// The length only: no output at all.
#[cfg(feature = "gzip-len")]
#[unsafe(no_mangle)]
pub extern "C" fn entry(src: *const u8, src_len: usize, max_len: usize) -> isize {
    let src = unsafe { core::slice::from_raw_parts(src, src_len) };
    compcol::gzip::decompressed_len(src, max_len).map_or(-1, |len| len as isize)
}

/// The one-shot encoders: slice to slice, with the caller's table.
macro_rules! compress_entry {
    ($feature:literal, $module:ident) => {
        #[cfg(feature = $feature)]
        #[unsafe(no_mangle)]
        pub extern "C" fn entry(
            src: *const u8,
            src_len: usize,
            dst: *mut u8,
            dst_len: usize,
            table: *mut u16,
            table_len: usize,
        ) -> isize {
            let src = unsafe { core::slice::from_raw_parts(src, src_len) };
            let dst = unsafe { core::slice::from_raw_parts_mut(dst, dst_len) };
            let table = unsafe { core::slice::from_raw_parts_mut(table, table_len) };
            compcol::$module::compress(src, table, dst).map_or(-1, |len| len as isize)
        }
    };
}

compress_entry!("gzip-compress", gzip);
compress_entry!("zlib-compress", zlib);
compress_entry!("deflate-compress", deflate);

/// Encode, then decode the result: both halves in one binary.
#[cfg(feature = "gzip-both")]
static mut BOTH: (compcol::gzip::Encoder, compcol::gzip::Decoder) =
    (compcol::gzip::Encoder::new(), compcol::gzip::Decoder::new());

#[cfg(feature = "gzip-both")]
#[unsafe(no_mangle)]
pub extern "C" fn entry(
    src: *const u8,
    src_len: usize,
    mid: *mut u8,
    mid_len: usize,
    dst: *mut u8,
    dst_len: usize,
) -> isize {
    let src = unsafe { core::slice::from_raw_parts(src, src_len) };
    let mid = unsafe { core::slice::from_raw_parts_mut(mid, mid_len) };
    let dst = unsafe { core::slice::from_raw_parts_mut(dst, dst_len) };
    let (enc, dec) = unsafe { &mut *core::ptr::addr_of_mut!(BOTH) };
    enc.reset();
    dec.reset();
    let n = encode(enc, src, mid);
    if n < 0 {
        return n;
    }
    decode(dec, mid.get(..n as usize).unwrap_or(&[]), dst)
}
