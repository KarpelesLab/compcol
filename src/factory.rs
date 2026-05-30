//! Runtime by-name lookup of algorithms.
//!
//! Only the algorithms whose Cargo features are enabled appear in
//! [`names`] and are resolvable by [`encoder_by_name`] / [`decoder_by_name`].
//! Requires the `alloc` feature (pulled in automatically by the `factory`
//! feature) because the returned trait objects are heap-allocated.

extern crate alloc;
use alloc::boxed::Box;

use crate::traits::{Algorithm, Decoder, Encoder};

/// Build an encoder for the algorithm named `name`, or `None` if no algorithm
/// is compiled in under that name.
pub fn encoder_by_name(name: &str) -> Option<Box<dyn Encoder>> {
    match name {
        #[cfg(feature = "rle")]
        crate::rle::Rle::NAME => Some(Box::new(<crate::rle::Rle as Algorithm>::encoder())),
        #[cfg(feature = "rle90")]
        crate::rle90::Rle90::NAME => Some(Box::new(<crate::rle90::Rle90 as Algorithm>::encoder())),
        #[cfg(feature = "deflate")]
        crate::deflate::Deflate::NAME => {
            Some(Box::new(<crate::deflate::Deflate as Algorithm>::encoder()))
        }
        #[cfg(feature = "deflate64")]
        crate::deflate64::Deflate64::NAME => Some(Box::new(
            <crate::deflate64::Deflate64 as Algorithm>::encoder(),
        )),
        #[cfg(feature = "zlib")]
        crate::zlib::Zlib::NAME => Some(Box::new(<crate::zlib::Zlib as Algorithm>::encoder())),
        #[cfg(feature = "gzip")]
        crate::gzip::Gzip::NAME => Some(Box::new(<crate::gzip::Gzip as Algorithm>::encoder())),
        #[cfg(feature = "lzma")]
        crate::lzma::Lzma::NAME => Some(Box::new(<crate::lzma::Lzma as Algorithm>::encoder())),
        #[cfg(feature = "xz")]
        crate::xz::Xz::NAME => Some(Box::new(<crate::xz::Xz as Algorithm>::encoder())),
        #[cfg(feature = "zstd")]
        crate::zstd::Zstd::NAME => Some(Box::new(<crate::zstd::Zstd as Algorithm>::encoder())),
        #[cfg(feature = "brotli")]
        crate::brotli::Brotli::NAME => {
            Some(Box::new(<crate::brotli::Brotli as Algorithm>::encoder()))
        }
        #[cfg(feature = "lz4")]
        crate::lz4::Lz4::NAME => Some(Box::new(<crate::lz4::Lz4 as Algorithm>::encoder())),
        #[cfg(feature = "lz4")]
        crate::lz4::frame::LZ4Frame::NAME => Some(Box::new(
            <crate::lz4::frame::LZ4Frame as Algorithm>::encoder(),
        )),
        #[cfg(feature = "lz5")]
        crate::lz5::Lz5::NAME => Some(Box::new(<crate::lz5::Lz5 as Algorithm>::encoder())),
        #[cfg(feature = "snappy")]
        crate::snappy::Snappy::NAME => {
            Some(Box::new(<crate::snappy::Snappy as Algorithm>::encoder()))
        }
        #[cfg(feature = "lzw")]
        crate::lzw::Lzw::NAME => Some(Box::new(<crate::lzw::Lzw as Algorithm>::encoder())),
        #[cfg(feature = "lzss")]
        crate::lzss::Lzss::NAME => Some(Box::new(<crate::lzss::Lzss as Algorithm>::encoder())),
        #[cfg(feature = "lzo")]
        crate::lzo::Lzo::NAME => Some(Box::new(<crate::lzo::Lzo as Algorithm>::encoder())),
        #[cfg(feature = "lzx")]
        crate::lzx::Lzx::NAME => Some(Box::new(<crate::lzx::Lzx as Algorithm>::encoder())),
        #[cfg(feature = "amiga_lzx")]
        crate::amiga_lzx::AmigaLzx::NAME => Some(Box::new(
            <crate::amiga_lzx::AmigaLzx as Algorithm>::encoder(),
        )),
        #[cfg(feature = "quantum")]
        crate::quantum::Quantum::NAME => {
            Some(Box::new(<crate::quantum::Quantum as Algorithm>::encoder()))
        }
        #[cfg(feature = "lzfse")]
        crate::lzfse::Lzfse::NAME => Some(Box::new(<crate::lzfse::Lzfse as Algorithm>::encoder())),
        #[cfg(feature = "adc")]
        crate::adc::Adc::NAME => Some(Box::new(<crate::adc::Adc as Algorithm>::encoder())),
        #[cfg(feature = "ppmd")]
        crate::ppmd::Ppmd::NAME => Some(Box::new(<crate::ppmd::Ppmd as Algorithm>::encoder())),
        #[cfg(feature = "lznt1")]
        crate::lznt1::Lznt1::NAME => Some(Box::new(<crate::lznt1::Lznt1 as Algorithm>::encoder())),
        #[cfg(feature = "bzip2")]
        crate::bzip2::Bzip2::NAME => Some(Box::new(<crate::bzip2::Bzip2 as Algorithm>::encoder())),
        #[cfg(feature = "xpress_huffman")]
        crate::xpress_huffman::XpressHuffman::NAME => Some(Box::new(
            <crate::xpress_huffman::XpressHuffman as Algorithm>::encoder(),
        )),
        #[cfg(feature = "xpress")]
        crate::xpress::Xpress::NAME => {
            Some(Box::new(<crate::xpress::Xpress as Algorithm>::encoder()))
        }
        #[cfg(feature = "packbits")]
        crate::packbits::PackBits::NAME => {
            Some(Box::new(<crate::packbits::PackBits as Algorithm>::encoder()))
        }
        #[cfg(feature = "zip_implode")]
        crate::zip_implode::ZipImplode::NAME => Some(Box::new(
            <crate::zip_implode::ZipImplode as Algorithm>::encoder(),
        )),
        #[cfg(feature = "lzs")]
        crate::lzs::Lzs::NAME => Some(Box::new(<crate::lzs::Lzs as Algorithm>::encoder())),
        #[cfg(feature = "lzham")]
        crate::lzham::Lzham::NAME => Some(Box::new(<crate::lzham::Lzham as Algorithm>::encoder())),
        #[cfg(feature = "sit13")]
        crate::sit13::Sit13::NAME => Some(Box::new(<crate::sit13::Sit13 as Algorithm>::encoder())),
        #[cfg(feature = "lzah")]
        crate::lzah::Lzah::NAME => Some(Box::new(<crate::lzah::Lzah as Algorithm>::encoder())),
        #[cfg(feature = "arsenic")]
        crate::arsenic::Arsenic::NAME => {
            Some(Box::new(<crate::arsenic::Arsenic as Algorithm>::encoder()))
        }
        #[cfg(feature = "rar1")]
        crate::rar1::Rar1::NAME => Some(Box::new(<crate::rar1::Rar1 as Algorithm>::encoder())),
        #[cfg(feature = "rar2")]
        crate::rar2::Rar2::NAME => Some(Box::new(<crate::rar2::Rar2 as Algorithm>::encoder())),
        #[cfg(feature = "rar3")]
        crate::rar3::Rar3::NAME => Some(Box::new(<crate::rar3::Rar3 as Algorithm>::encoder())),
        #[cfg(feature = "rar5")]
        crate::rar5::Rar5::NAME => Some(Box::new(<crate::rar5::Rar5 as Algorithm>::encoder())),
        #[cfg(feature = "zip_shrink")]
        crate::zip_shrink::ZipShrink::NAME => Some(Box::new(
            <crate::zip_shrink::ZipShrink as Algorithm>::encoder(),
        )),
        #[cfg(feature = "zip_reduce")]
        crate::zip_reduce::ZipReduce::NAME => Some(Box::new(
            <crate::zip_reduce::ZipReduce as Algorithm>::encoder(),
        )),
        #[cfg(feature = "lha")]
        crate::lha::Lh1::NAME => Some(Box::new(<crate::lha::Lh1 as Algorithm>::encoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh4::NAME => Some(Box::new(<crate::lha::Lh4 as Algorithm>::encoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh5::NAME => Some(Box::new(<crate::lha::Lh5 as Algorithm>::encoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh6::NAME => Some(Box::new(<crate::lha::Lh6 as Algorithm>::encoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh7::NAME => Some(Box::new(<crate::lha::Lh7 as Algorithm>::encoder())),
        #[cfg(feature = "bcj")]
        crate::bcj::BcjX86::NAME => Some(Box::new(<crate::bcj::BcjX86 as Algorithm>::encoder())),
        #[cfg(feature = "bcj")]
        crate::bcj::BcjArm::NAME => Some(Box::new(<crate::bcj::BcjArm as Algorithm>::encoder())),
        #[cfg(feature = "bcj")]
        crate::bcj::BcjArmThumb::NAME => {
            Some(Box::new(<crate::bcj::BcjArmThumb as Algorithm>::encoder()))
        }
        #[cfg(feature = "bcj")]
        crate::bcj::BcjArm64::NAME => {
            Some(Box::new(<crate::bcj::BcjArm64 as Algorithm>::encoder()))
        }
        #[cfg(feature = "bcj")]
        crate::bcj::BcjPpc::NAME => Some(Box::new(<crate::bcj::BcjPpc as Algorithm>::encoder())),
        #[cfg(feature = "bcj")]
        crate::bcj::BcjSparc::NAME => {
            Some(Box::new(<crate::bcj::BcjSparc as Algorithm>::encoder()))
        }
        #[cfg(feature = "bcj")]
        crate::bcj::BcjIa64::NAME => Some(Box::new(<crate::bcj::BcjIa64 as Algorithm>::encoder())),
        #[cfg(feature = "bcj")]
        crate::bcj::BcjRiscV::NAME => {
            Some(Box::new(<crate::bcj::BcjRiscV as Algorithm>::encoder()))
        }
        #[cfg(feature = "delta")]
        crate::delta::Delta::NAME => Some(Box::new(<crate::delta::Delta as Algorithm>::encoder())),
        #[cfg(feature = "arc_crunch")]
        crate::arc_crunch::ArcCrunch::NAME => Some(Box::new(
            <crate::arc_crunch::ArcCrunch as Algorithm>::encoder(),
        )),
        #[cfg(feature = "arc_squeeze")]
        crate::arc_squeeze::ArcSqueeze::NAME => Some(Box::new(
            <crate::arc_squeeze::ArcSqueeze as Algorithm>::encoder(),
        )),
        _ => None,
    }
}

/// Build an encoder for `name` configured at the supplied compression
/// `level`.
///
/// For algorithms with a level/quality knob (`deflate`, `zlib`, `gzip`,
/// `lzma`, `xz`, `zstd`, `brotli`) the level is plumbed into the
/// `EncoderConfig` and clamped to that algorithm's valid range:
///
/// * `deflate`/`zlib`/`gzip`: 1..=9, default 6
/// * `lzma`/`xz`: 0..=9, default 6
/// * `zstd`: 1..=22, default 3
/// * `brotli` quality: 0..=11, default 6
///
/// For algorithms without a level (everything else) the parameter is
/// ignored and the default-config encoder is returned. The CLI uses
/// this so a single `-l/--level N` flag works for every leveled
/// algorithm without branching at the call site.
pub fn encoder_by_name_with_level(name: &str, level: u8) -> Option<Box<dyn Encoder>> {
    match name {
        #[cfg(feature = "deflate")]
        crate::deflate::Deflate::NAME => Some(Box::new(
            <crate::deflate::Deflate as Algorithm>::encoder_with(crate::deflate::EncoderConfig {
                level,
            }),
        )),
        #[cfg(feature = "deflate64")]
        crate::deflate64::Deflate64::NAME => Some(Box::new(
            <crate::deflate64::Deflate64 as Algorithm>::encoder_with(
                crate::deflate64::EncoderConfig { level },
            ),
        )),
        #[cfg(feature = "zlib")]
        crate::zlib::Zlib::NAME => Some(Box::new(<crate::zlib::Zlib as Algorithm>::encoder_with(
            crate::zlib::EncoderConfig { level },
        ))),
        #[cfg(feature = "gzip")]
        crate::gzip::Gzip::NAME => Some(Box::new(<crate::gzip::Gzip as Algorithm>::encoder_with(
            crate::gzip::EncoderConfig { level },
        ))),
        #[cfg(feature = "lzma")]
        crate::lzma::Lzma::NAME => Some(Box::new(<crate::lzma::Lzma as Algorithm>::encoder_with(
            crate::lzma::EncoderConfig { level },
        ))),
        #[cfg(feature = "xz")]
        crate::xz::Xz::NAME => Some(Box::new(<crate::xz::Xz as Algorithm>::encoder_with(
            crate::xz::EncoderConfig { level },
        ))),
        #[cfg(feature = "zstd")]
        crate::zstd::Zstd::NAME => Some(Box::new(<crate::zstd::Zstd as Algorithm>::encoder_with(
            crate::zstd::EncoderConfig { level },
        ))),
        #[cfg(feature = "brotli")]
        crate::brotli::Brotli::NAME => Some(Box::new(
            <crate::brotli::Brotli as Algorithm>::encoder_with(crate::brotli::EncoderConfig {
                quality: level,
            }),
        )),
        #[cfg(feature = "bzip2")]
        crate::bzip2::Bzip2::NAME => Some(Box::new(
            <crate::bzip2::Bzip2 as Algorithm>::encoder_with(crate::bzip2::EncoderConfig { level }),
        )),
        // Non-leveled algorithms: ignore `level`, return default encoder.
        _ => encoder_by_name(name),
    }
}

/// Build a decoder for the algorithm named `name`, or `None` if no algorithm
/// is compiled in under that name.
pub fn decoder_by_name(name: &str) -> Option<Box<dyn Decoder>> {
    match name {
        #[cfg(feature = "rle")]
        crate::rle::Rle::NAME => Some(Box::new(<crate::rle::Rle as Algorithm>::decoder())),
        #[cfg(feature = "rle90")]
        crate::rle90::Rle90::NAME => Some(Box::new(<crate::rle90::Rle90 as Algorithm>::decoder())),
        #[cfg(feature = "deflate")]
        crate::deflate::Deflate::NAME => {
            Some(Box::new(<crate::deflate::Deflate as Algorithm>::decoder()))
        }
        #[cfg(feature = "deflate64")]
        crate::deflate64::Deflate64::NAME => Some(Box::new(
            <crate::deflate64::Deflate64 as Algorithm>::decoder(),
        )),
        #[cfg(feature = "zlib")]
        crate::zlib::Zlib::NAME => Some(Box::new(<crate::zlib::Zlib as Algorithm>::decoder())),
        #[cfg(feature = "gzip")]
        crate::gzip::Gzip::NAME => Some(Box::new(<crate::gzip::Gzip as Algorithm>::decoder())),
        #[cfg(feature = "lzma")]
        crate::lzma::Lzma::NAME => Some(Box::new(<crate::lzma::Lzma as Algorithm>::decoder())),
        #[cfg(feature = "xz")]
        crate::xz::Xz::NAME => Some(Box::new(<crate::xz::Xz as Algorithm>::decoder())),
        #[cfg(feature = "zstd")]
        crate::zstd::Zstd::NAME => Some(Box::new(<crate::zstd::Zstd as Algorithm>::decoder())),
        #[cfg(feature = "brotli")]
        crate::brotli::Brotli::NAME => {
            Some(Box::new(<crate::brotli::Brotli as Algorithm>::decoder()))
        }
        #[cfg(feature = "lz4")]
        crate::lz4::Lz4::NAME => Some(Box::new(<crate::lz4::Lz4 as Algorithm>::decoder())),
        #[cfg(feature = "lz4")]
        crate::lz4::frame::LZ4Frame::NAME => Some(Box::new(
            <crate::lz4::frame::LZ4Frame as Algorithm>::decoder(),
        )),
        #[cfg(feature = "lz5")]
        crate::lz5::Lz5::NAME => Some(Box::new(<crate::lz5::Lz5 as Algorithm>::decoder())),
        #[cfg(feature = "snappy")]
        crate::snappy::Snappy::NAME => {
            Some(Box::new(<crate::snappy::Snappy as Algorithm>::decoder()))
        }
        #[cfg(feature = "lzw")]
        crate::lzw::Lzw::NAME => Some(Box::new(<crate::lzw::Lzw as Algorithm>::decoder())),
        #[cfg(feature = "lzss")]
        crate::lzss::Lzss::NAME => Some(Box::new(<crate::lzss::Lzss as Algorithm>::decoder())),
        #[cfg(feature = "lzo")]
        crate::lzo::Lzo::NAME => Some(Box::new(<crate::lzo::Lzo as Algorithm>::decoder())),
        #[cfg(feature = "lzx")]
        crate::lzx::Lzx::NAME => Some(Box::new(<crate::lzx::Lzx as Algorithm>::decoder())),
        #[cfg(feature = "amiga_lzx")]
        crate::amiga_lzx::AmigaLzx::NAME => Some(Box::new(
            <crate::amiga_lzx::AmigaLzx as Algorithm>::decoder(),
        )),
        #[cfg(feature = "quantum")]
        crate::quantum::Quantum::NAME => {
            Some(Box::new(<crate::quantum::Quantum as Algorithm>::decoder()))
        }
        #[cfg(feature = "lzfse")]
        crate::lzfse::Lzfse::NAME => Some(Box::new(<crate::lzfse::Lzfse as Algorithm>::decoder())),
        #[cfg(feature = "adc")]
        crate::adc::Adc::NAME => Some(Box::new(<crate::adc::Adc as Algorithm>::decoder())),
        #[cfg(feature = "ppmd")]
        crate::ppmd::Ppmd::NAME => Some(Box::new(<crate::ppmd::Ppmd as Algorithm>::decoder())),
        #[cfg(feature = "lznt1")]
        crate::lznt1::Lznt1::NAME => Some(Box::new(<crate::lznt1::Lznt1 as Algorithm>::decoder())),
        #[cfg(feature = "bzip2")]
        crate::bzip2::Bzip2::NAME => Some(Box::new(<crate::bzip2::Bzip2 as Algorithm>::decoder())),
        #[cfg(feature = "xpress_huffman")]
        crate::xpress_huffman::XpressHuffman::NAME => Some(Box::new(
            <crate::xpress_huffman::XpressHuffman as Algorithm>::decoder(),
        )),
        #[cfg(feature = "xpress")]
        crate::xpress::Xpress::NAME => {
            Some(Box::new(<crate::xpress::Xpress as Algorithm>::decoder()))
        }
        #[cfg(feature = "packbits")]
        crate::packbits::PackBits::NAME => {
            Some(Box::new(<crate::packbits::PackBits as Algorithm>::decoder()))
        }
        #[cfg(feature = "zip_implode")]
        crate::zip_implode::ZipImplode::NAME => Some(Box::new(
            <crate::zip_implode::ZipImplode as Algorithm>::decoder(),
        )),
        #[cfg(feature = "lzs")]
        crate::lzs::Lzs::NAME => Some(Box::new(<crate::lzs::Lzs as Algorithm>::decoder())),
        #[cfg(feature = "lzham")]
        crate::lzham::Lzham::NAME => Some(Box::new(<crate::lzham::Lzham as Algorithm>::decoder())),
        #[cfg(feature = "sit13")]
        crate::sit13::Sit13::NAME => Some(Box::new(<crate::sit13::Sit13 as Algorithm>::decoder())),
        #[cfg(feature = "lzah")]
        crate::lzah::Lzah::NAME => Some(Box::new(<crate::lzah::Lzah as Algorithm>::decoder())),
        #[cfg(feature = "arsenic")]
        crate::arsenic::Arsenic::NAME => {
            Some(Box::new(<crate::arsenic::Arsenic as Algorithm>::decoder()))
        }
        #[cfg(feature = "rar1")]
        crate::rar1::Rar1::NAME => Some(Box::new(<crate::rar1::Rar1 as Algorithm>::decoder())),
        #[cfg(feature = "rar2")]
        crate::rar2::Rar2::NAME => Some(Box::new(<crate::rar2::Rar2 as Algorithm>::decoder())),
        #[cfg(feature = "rar3")]
        crate::rar3::Rar3::NAME => Some(Box::new(<crate::rar3::Rar3 as Algorithm>::decoder())),
        #[cfg(feature = "rar5")]
        crate::rar5::Rar5::NAME => Some(Box::new(<crate::rar5::Rar5 as Algorithm>::decoder())),
        #[cfg(feature = "zip_shrink")]
        crate::zip_shrink::ZipShrink::NAME => Some(Box::new(
            <crate::zip_shrink::ZipShrink as Algorithm>::decoder(),
        )),
        #[cfg(feature = "zip_reduce")]
        crate::zip_reduce::ZipReduce::NAME => Some(Box::new(
            <crate::zip_reduce::ZipReduce as Algorithm>::decoder(),
        )),
        #[cfg(feature = "lha")]
        crate::lha::Lh1::NAME => Some(Box::new(<crate::lha::Lh1 as Algorithm>::decoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh4::NAME => Some(Box::new(<crate::lha::Lh4 as Algorithm>::decoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh5::NAME => Some(Box::new(<crate::lha::Lh5 as Algorithm>::decoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh6::NAME => Some(Box::new(<crate::lha::Lh6 as Algorithm>::decoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh7::NAME => Some(Box::new(<crate::lha::Lh7 as Algorithm>::decoder())),
        #[cfg(feature = "bcj")]
        crate::bcj::BcjX86::NAME => Some(Box::new(<crate::bcj::BcjX86 as Algorithm>::decoder())),
        #[cfg(feature = "bcj")]
        crate::bcj::BcjArm::NAME => Some(Box::new(<crate::bcj::BcjArm as Algorithm>::decoder())),
        #[cfg(feature = "bcj")]
        crate::bcj::BcjArmThumb::NAME => {
            Some(Box::new(<crate::bcj::BcjArmThumb as Algorithm>::decoder()))
        }
        #[cfg(feature = "bcj")]
        crate::bcj::BcjArm64::NAME => {
            Some(Box::new(<crate::bcj::BcjArm64 as Algorithm>::decoder()))
        }
        #[cfg(feature = "bcj")]
        crate::bcj::BcjPpc::NAME => Some(Box::new(<crate::bcj::BcjPpc as Algorithm>::decoder())),
        #[cfg(feature = "bcj")]
        crate::bcj::BcjSparc::NAME => {
            Some(Box::new(<crate::bcj::BcjSparc as Algorithm>::decoder()))
        }
        #[cfg(feature = "bcj")]
        crate::bcj::BcjIa64::NAME => Some(Box::new(<crate::bcj::BcjIa64 as Algorithm>::decoder())),
        #[cfg(feature = "bcj")]
        crate::bcj::BcjRiscV::NAME => {
            Some(Box::new(<crate::bcj::BcjRiscV as Algorithm>::decoder()))
        }
        #[cfg(feature = "delta")]
        crate::delta::Delta::NAME => Some(Box::new(<crate::delta::Delta as Algorithm>::decoder())),
        #[cfg(feature = "arc_crunch")]
        crate::arc_crunch::ArcCrunch::NAME => Some(Box::new(
            <crate::arc_crunch::ArcCrunch as Algorithm>::decoder(),
        )),
        #[cfg(feature = "arc_squeeze")]
        crate::arc_squeeze::ArcSqueeze::NAME => Some(Box::new(
            <crate::arc_squeeze::ArcSqueeze as Algorithm>::decoder(),
        )),
        _ => None,
    }
}

/// Conventional filename extension (without the leading `.`) for the given
/// algorithm, or `None` if the algorithm isn't compiled in or has no
/// conventional extension.
///
/// Used by the `compcol` CLI to derive `<input>.<ext>` output paths in
/// gzip-style in-place mode.
pub const fn extension(name: &str) -> Option<&'static str> {
    // String literals match on byte-identical content, which `const fn`
    // allows; can't use enum dispatch through trait objects in const context.
    if str_eq(name, "rle") && cfg!(feature = "rle") {
        return Some("rle");
    }
    if str_eq(name, "rle90") && cfg!(feature = "rle90") {
        return Some("rle90");
    }
    if str_eq(name, "deflate") && cfg!(feature = "deflate") {
        return Some("deflate");
    }
    if str_eq(name, "deflate64") && cfg!(feature = "deflate64") {
        return Some("deflate64");
    }
    if str_eq(name, "zlib") && cfg!(feature = "zlib") {
        return Some("zz");
    }
    if str_eq(name, "gzip") && cfg!(feature = "gzip") {
        return Some("gz");
    }
    if str_eq(name, "lzma") && cfg!(feature = "lzma") {
        return Some("lzma");
    }
    if str_eq(name, "xz") && cfg!(feature = "xz") {
        return Some("xz");
    }
    if str_eq(name, "zstd") && cfg!(feature = "zstd") {
        return Some("zst");
    }
    if str_eq(name, "brotli") && cfg!(feature = "brotli") {
        return Some("br");
    }
    if str_eq(name, "lz4") && cfg!(feature = "lz4") {
        return Some("lz4");
    }
    if str_eq(name, "lz4-frame") && cfg!(feature = "lz4") {
        return Some("lz4");
    }
    if str_eq(name, "lz5") && cfg!(feature = "lz5") {
        return Some("liz");
    }
    if str_eq(name, "snappy") && cfg!(feature = "snappy") {
        return Some("sz");
    }
    if str_eq(name, "lzw") && cfg!(feature = "lzw") {
        return Some("lzw");
    }
    if str_eq(name, "lzss") && cfg!(feature = "lzss") {
        return Some("lzss");
    }
    if str_eq(name, "lzo") && cfg!(feature = "lzo") {
        return Some("lzo");
    }
    if str_eq(name, "lzx") && cfg!(feature = "lzx") {
        return Some("lzx");
    }
    if str_eq(name, "quantum") && cfg!(feature = "quantum") {
        return Some("q");
    }
    if str_eq(name, "lzfse") && cfg!(feature = "lzfse") {
        return Some("lzfse");
    }
    if str_eq(name, "adc") && cfg!(feature = "adc") {
        return Some("adc");
    }
    if str_eq(name, "ppmd") && cfg!(feature = "ppmd") {
        return Some("ppmd");
    }
    if str_eq(name, "lznt1") && cfg!(feature = "lznt1") {
        return Some("lznt1");
    }
    if str_eq(name, "bzip2") && cfg!(feature = "bzip2") {
        return Some("bz2");
    }
    if str_eq(name, "xpress-huffman") && cfg!(feature = "xpress_huffman") {
        return Some("xph");
    }
    if str_eq(name, "xpress") && cfg!(feature = "xpress") {
        return Some("xpress");
    }
    if str_eq(name, "packbits") && cfg!(feature = "packbits") {
        return Some("packbits");
    }
    if str_eq(name, "zip-implode") && cfg!(feature = "zip_implode") {
        return Some("implode");
    }
    if str_eq(name, "lzs") && cfg!(feature = "lzs") {
        return Some("lzs");
    }
    if str_eq(name, "lzham") && cfg!(feature = "lzham") {
        return Some("lzham");
    }
    if str_eq(name, "sit13") && cfg!(feature = "sit13") {
        return Some("sit13");
    }
    if str_eq(name, "lzah") && cfg!(feature = "lzah") {
        return Some("lzah");
    }
    if str_eq(name, "arsenic") && cfg!(feature = "arsenic") {
        return Some("arsenic");
    }
    // All RAR versions share the .rar extension; the version is in-band in
    // the file header. The CLI's in-place mode will write to <input>.rar
    // and strip .rar on decode for any rar* algorithm.
    if str_eq(name, "rar1") && cfg!(feature = "rar1") {
        return Some("rar");
    }
    if str_eq(name, "rar2") && cfg!(feature = "rar2") {
        return Some("rar");
    }
    if str_eq(name, "rar3") && cfg!(feature = "rar3") {
        return Some("rar");
    }
    if str_eq(name, "rar5") && cfg!(feature = "rar5") {
        return Some("rar");
    }
    if str_eq(name, "zip-shrink") && cfg!(feature = "zip_shrink") {
        return Some("shrunk");
    }
    if str_eq(name, "zip-reduce") && cfg!(feature = "zip_reduce") {
        return Some("reduce");
    }
    // LHA methods all conventionally live in `.lzh` archives; the method
    // is in-band in the LHA header. The CLI's in-place mode writes to
    // `<input>.lzh`.
    if str_eq(name, "lh1") && cfg!(feature = "lha") {
        return Some("lzh");
    }
    if str_eq(name, "lh4") && cfg!(feature = "lha") {
        return Some("lzh");
    }
    if str_eq(name, "lh5") && cfg!(feature = "lha") {
        return Some("lzh");
    }
    if str_eq(name, "lh6") && cfg!(feature = "lha") {
        return Some("lzh");
    }
    if str_eq(name, "lh7") && cfg!(feature = "lha") {
        return Some("lzh");
    }
    // BCJ branch filters and the delta filter are pre-processors, not
    // standalone container formats; they have no conventional extension, so
    // the filter name doubles as the suffix the CLI appends.
    if str_eq(name, "bcj-x86") && cfg!(feature = "bcj") {
        return Some("bcj-x86");
    }
    if str_eq(name, "bcj-arm") && cfg!(feature = "bcj") {
        return Some("bcj-arm");
    }
    if str_eq(name, "bcj-armt") && cfg!(feature = "bcj") {
        return Some("bcj-armt");
    }
    if str_eq(name, "bcj-arm64") && cfg!(feature = "bcj") {
        return Some("bcj-arm64");
    }
    if str_eq(name, "bcj-ppc") && cfg!(feature = "bcj") {
        return Some("bcj-ppc");
    }
    if str_eq(name, "bcj-sparc") && cfg!(feature = "bcj") {
        return Some("bcj-sparc");
    }
    if str_eq(name, "bcj-ia64") && cfg!(feature = "bcj") {
        return Some("bcj-ia64");
    }
    if str_eq(name, "bcj-riscv") && cfg!(feature = "bcj") {
        return Some("bcj-riscv");
    }
    if str_eq(name, "delta") && cfg!(feature = "delta") {
        return Some("delta");
    }
    if str_eq(name, "crunch") && cfg!(feature = "arc_crunch") {
        return Some("arc");
    }
    if str_eq(name, "squeeze") && cfg!(feature = "arc_squeeze") {
        return Some("sqz");
    }
    None
}

/// Const-eval-friendly byte comparison.
const fn str_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// The names of every algorithm compiled into the current build, in stable
/// order. Useful for diagnostics, CLI `--list`, etc.
pub const fn names() -> &'static [&'static str] {
    &[
        #[cfg(feature = "rle")]
        crate::rle::Rle::NAME,
        #[cfg(feature = "rle90")]
        crate::rle90::Rle90::NAME,
        #[cfg(feature = "deflate")]
        crate::deflate::Deflate::NAME,
        #[cfg(feature = "deflate64")]
        crate::deflate64::Deflate64::NAME,
        #[cfg(feature = "zlib")]
        crate::zlib::Zlib::NAME,
        #[cfg(feature = "gzip")]
        crate::gzip::Gzip::NAME,
        #[cfg(feature = "lzma")]
        crate::lzma::Lzma::NAME,
        #[cfg(feature = "xz")]
        crate::xz::Xz::NAME,
        #[cfg(feature = "zstd")]
        crate::zstd::Zstd::NAME,
        #[cfg(feature = "brotli")]
        crate::brotli::Brotli::NAME,
        #[cfg(feature = "lz4")]
        crate::lz4::Lz4::NAME,
        #[cfg(feature = "lz4")]
        crate::lz4::frame::LZ4Frame::NAME,
        #[cfg(feature = "lz5")]
        crate::lz5::Lz5::NAME,
        #[cfg(feature = "snappy")]
        crate::snappy::Snappy::NAME,
        #[cfg(feature = "lzw")]
        crate::lzw::Lzw::NAME,
        #[cfg(feature = "lzss")]
        crate::lzss::Lzss::NAME,
        #[cfg(feature = "lzo")]
        crate::lzo::Lzo::NAME,
        #[cfg(feature = "lzx")]
        crate::lzx::Lzx::NAME,
        #[cfg(feature = "amiga_lzx")]
        crate::amiga_lzx::AmigaLzx::NAME,
        #[cfg(feature = "quantum")]
        crate::quantum::Quantum::NAME,
        #[cfg(feature = "lzfse")]
        crate::lzfse::Lzfse::NAME,
        #[cfg(feature = "adc")]
        crate::adc::Adc::NAME,
        #[cfg(feature = "ppmd")]
        crate::ppmd::Ppmd::NAME,
        #[cfg(feature = "lznt1")]
        crate::lznt1::Lznt1::NAME,
        #[cfg(feature = "bzip2")]
        crate::bzip2::Bzip2::NAME,
        #[cfg(feature = "xpress_huffman")]
        crate::xpress_huffman::XpressHuffman::NAME,
        #[cfg(feature = "xpress")]
        crate::xpress::Xpress::NAME,
        #[cfg(feature = "packbits")]
        crate::packbits::PackBits::NAME,
        #[cfg(feature = "zip_implode")]
        crate::zip_implode::ZipImplode::NAME,
        #[cfg(feature = "lzs")]
        crate::lzs::Lzs::NAME,
        #[cfg(feature = "lzham")]
        crate::lzham::Lzham::NAME,
        #[cfg(feature = "sit13")]
        crate::sit13::Sit13::NAME,
        #[cfg(feature = "lzah")]
        crate::lzah::Lzah::NAME,
        #[cfg(feature = "arsenic")]
        crate::arsenic::Arsenic::NAME,
        #[cfg(feature = "rar1")]
        crate::rar1::Rar1::NAME,
        #[cfg(feature = "rar2")]
        crate::rar2::Rar2::NAME,
        #[cfg(feature = "rar3")]
        crate::rar3::Rar3::NAME,
        #[cfg(feature = "rar5")]
        crate::rar5::Rar5::NAME,
        #[cfg(feature = "zip_shrink")]
        crate::zip_shrink::ZipShrink::NAME,
        #[cfg(feature = "zip_reduce")]
        crate::zip_reduce::ZipReduce::NAME,
        #[cfg(feature = "lha")]
        crate::lha::Lh1::NAME,
        #[cfg(feature = "lha")]
        crate::lha::Lh4::NAME,
        #[cfg(feature = "lha")]
        crate::lha::Lh5::NAME,
        #[cfg(feature = "lha")]
        crate::lha::Lh6::NAME,
        #[cfg(feature = "lha")]
        crate::lha::Lh7::NAME,
        #[cfg(feature = "bcj")]
        crate::bcj::BcjX86::NAME,
        #[cfg(feature = "bcj")]
        crate::bcj::BcjArm::NAME,
        #[cfg(feature = "bcj")]
        crate::bcj::BcjArmThumb::NAME,
        #[cfg(feature = "bcj")]
        crate::bcj::BcjArm64::NAME,
        #[cfg(feature = "bcj")]
        crate::bcj::BcjPpc::NAME,
        #[cfg(feature = "bcj")]
        crate::bcj::BcjSparc::NAME,
        #[cfg(feature = "bcj")]
        crate::bcj::BcjIa64::NAME,
        #[cfg(feature = "bcj")]
        crate::bcj::BcjRiscV::NAME,
        #[cfg(feature = "delta")]
        crate::delta::Delta::NAME,
        #[cfg(feature = "arc_crunch")]
        crate::arc_crunch::ArcCrunch::NAME,
        #[cfg(feature = "arc_squeeze")]
        crate::arc_squeeze::ArcSqueeze::NAME,
    ]
}
