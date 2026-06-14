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
        #[cfg(feature = "lzma2")]
        crate::lzma2::Lzma2::NAME => Some(Box::new(<crate::lzma2::Lzma2 as Algorithm>::encoder())),
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
        crate::lha::Lh2::NAME => Some(Box::new(<crate::lha::Lh2 as Algorithm>::encoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh4::NAME => Some(Box::new(<crate::lha::Lh4 as Algorithm>::encoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh5::NAME => Some(Box::new(<crate::lha::Lh5 as Algorithm>::encoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh6::NAME => Some(Box::new(<crate::lha::Lh6 as Algorithm>::encoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh7::NAME => Some(Box::new(<crate::lha::Lh7 as Algorithm>::encoder())),
        #[cfg(feature = "hpack")]
        crate::hpack::Http2Huffman::NAME => Some(Box::new(
            <crate::hpack::Http2Huffman as Algorithm>::encoder(),
        )),
        #[cfg(feature = "huffman")]
        crate::huffman_codec::Huffman::NAME => Some(Box::new(
            <crate::huffman_codec::Huffman as Algorithm>::encoder(),
        )),
        #[cfg(feature = "rangecoder")]
        crate::rangecoder::RangeCoder::NAME => Some(Box::new(
            <crate::rangecoder::RangeCoder as Algorithm>::encoder(),
        )),
        #[cfg(feature = "mtf")]
        crate::mtf::Mtf::NAME => Some(Box::new(<crate::mtf::Mtf as Algorithm>::encoder())),
        #[cfg(feature = "bwt")]
        crate::bwt::Bwt::NAME => Some(Box::new(<crate::bwt::Bwt as Algorithm>::encoder())),
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
        #[cfg(feature = "arc_squash")]
        crate::arc_squash::ArcSquash::NAME => Some(Box::new(
            <crate::arc_squash::ArcSquash as Algorithm>::encoder(),
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
                ..crate::deflate::EncoderConfig::default()
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
        #[cfg(feature = "lzma2")]
        crate::lzma2::Lzma2::NAME => Some(Box::new(<crate::lzma2::Lzma2 as Algorithm>::decoder())),
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
        crate::lha::Lh2::NAME => Some(Box::new(<crate::lha::Lh2 as Algorithm>::decoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh4::NAME => Some(Box::new(<crate::lha::Lh4 as Algorithm>::decoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh5::NAME => Some(Box::new(<crate::lha::Lh5 as Algorithm>::decoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh6::NAME => Some(Box::new(<crate::lha::Lh6 as Algorithm>::decoder())),
        #[cfg(feature = "lha")]
        crate::lha::Lh7::NAME => Some(Box::new(<crate::lha::Lh7 as Algorithm>::decoder())),
        #[cfg(feature = "hpack")]
        crate::hpack::Http2Huffman::NAME => Some(Box::new(
            <crate::hpack::Http2Huffman as Algorithm>::decoder(),
        )),
        #[cfg(feature = "huffman")]
        crate::huffman_codec::Huffman::NAME => Some(Box::new(
            <crate::huffman_codec::Huffman as Algorithm>::decoder(),
        )),
        #[cfg(feature = "rangecoder")]
        crate::rangecoder::RangeCoder::NAME => Some(Box::new(
            <crate::rangecoder::RangeCoder as Algorithm>::decoder(),
        )),
        #[cfg(feature = "mtf")]
        crate::mtf::Mtf::NAME => Some(Box::new(<crate::mtf::Mtf as Algorithm>::decoder())),
        #[cfg(feature = "bwt")]
        crate::bwt::Bwt::NAME => Some(Box::new(<crate::bwt::Bwt as Algorithm>::decoder())),
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
        #[cfg(feature = "arc_squash")]
        crate::arc_squash::ArcSquash::NAME => Some(Box::new(
            <crate::arc_squash::ArcSquash as Algorithm>::decoder(),
        )),
        _ => None,
    }
}

/// Sniff `prefix` (a leading slice of a compressed stream) and return the
/// algorithm NAME of the most likely codec, or `None` if unrecognized.
///
/// Matching is by well-known magic-byte signatures. Each arm is gated on the
/// relevant codec feature, so `detect` only ever names a codec that is
/// actually compiled into this build: a recognized magic for a disabled
/// feature yields `None` rather than an unusable name.
///
/// The function is pure and total over any input: short slices and arbitrary
/// bytes simply return `None`. It never panics. Checks are ordered so that
/// longer / stronger magics are tested before weaker ones, and the matching
/// is deliberately conservative — when a signature is ambiguous or
/// low-confidence (e.g. raw `.lzma`), `detect` prefers `None` over a wrong
/// guess.
///
/// # Magic signatures recognized
///
/// | Format        | Bytes (hex)                  | Returned name           |
/// |---------------|------------------------------|-------------------------|
/// | xz            | `FD 37 7A 58 5A 00`          | `"xz"`                  |
/// | RAR 5         | `52 61 72 21 1A 07 01 00`    | `"rar5"`                |
/// | RAR 1.5–4     | `52 61 72 21 1A 07 00`       | `"rar3"` (see below)    |
/// | StuffIt classic | `"SIT!"` … `"rLau"` @ 10   | `"arsenic"` (container) |
/// | StuffIt 5     | `"StuffIt"`                  | `"arsenic"` (container) |
/// | gzip          | `1F 8B`                      | `"gzip"`                |
/// | zstd          | `28 B5 2F FD`                | `"zstd"`                |
/// | bzip2         | `42 5A 68` (`"BZh"`)         | `"bzip2"`               |
/// | lz4 frame     | `04 22 4D 18`                | `"lz4-frame"`           |
/// | zlib          | `78 xx` with `(CMF*256+FLG)%31==0` | `"zlib"`          |
///
/// # Formats deliberately not detected
///
/// * **brotli** has no magic number at all; a brotli stream starts directly
///   with the WBITS bits, so it cannot be sniffed and is never returned.
/// * **raw `.lzma`** begins with a 1-byte properties value (commonly `0x5D`)
///   followed by a 4-byte little-endian dictionary size. There is no true
///   magic — `5D 00 00` collides with ordinary data — so it is omitted to
///   avoid false positives. Use an explicit algorithm for raw LZMA.
///
/// # Containers, not single codecs
///
/// RAR and StuffIt are **archive containers** that hold per-member streams,
/// each potentially using a different codec; this crate's `rar*` / `arsenic`
/// decoders operate on a single member payload, not on the container framing.
/// `detect` recognizes the container magic and returns a representative codec
/// name (the newest decoder this build provides for that family) purely as a
/// format hint. A caller that wants to actually extract members must parse the
/// container directory first and feed each member to the appropriate decoder;
/// piping a whole `.rar` / `.sit` file straight into the named decoder will
/// not work. RAR version disambiguation beyond rar4-vs-rar5 (i.e. rar1 / rar2
/// / rar3) needs deeper header parsing, so the rar4-era magic maps to a single
/// representative (`rar3`).
pub fn detect(prefix: &[u8]) -> Option<&'static str> {
    let p = prefix;

    // ── Long / strong magics first ──────────────────────────────────────

    // xz: 0xFD '7' 'z' 'X' 'Z' 0x00 (6-byte stream header magic).
    // The XZ File Format §2.1.1.1.
    #[cfg(feature = "xz")]
    if p.starts_with(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00]) {
        return Some(crate::xz::Xz::NAME);
    }

    // RAR: "Rar!\x1A\x07" then a version byte.
    //   0x00            → RAR 1.5–4.x archive  (RARv4 header block format)
    //   0x01 0x00       → RAR 5.0 archive
    // See the RAR archive format notes (RARLAB). RAR is a *container*; this
    // returns a representative member-codec name as a format hint only.
    if p.starts_with(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07]) {
        match p.get(6) {
            #[cfg(feature = "rar5")]
            Some(0x01) if p.get(7) == Some(&0x00) => return Some(crate::rar5::Rar5::NAME),
            // RAR4-era magic. The exact 1.5/2/3 split needs deeper header
            // parsing; return the newest rar4-family decoder compiled in as a
            // representative hint.
            Some(0x00) => {
                #[cfg(feature = "rar3")]
                return Some(crate::rar3::Rar3::NAME);
                #[cfg(all(not(feature = "rar3"), feature = "rar2"))]
                return Some(crate::rar2::Rar2::NAME);
                #[cfg(all(not(feature = "rar3"), not(feature = "rar2"), feature = "rar1"))]
                return Some(crate::rar1::Rar1::NAME);
            }
            _ => {}
        }
    }

    // StuffIt classic: bytes[0..4] == "SIT!" AND bytes[10..14] == "rLau".
    // (The 4-byte tag plus the "rLau" creator signature at offset 10 is what
    // distinguishes a real StuffIt 1–4 archive from incidental "SIT!" data.)
    // This is a *container*; "arsenic" is returned only as a StuffIt format
    // hint — the caller must parse the archive directory to extract members.
    #[cfg(feature = "arsenic")]
    if p.len() >= 14 && &p[0..4] == b"SIT!" && &p[10..14] == b"rLau" {
        return Some(crate::arsenic::Arsenic::NAME);
    }

    // StuffIt 5: ASCII "StuffIt" prefix (the StuffIt 5 archive header begins
    // with the literal magic string "StuffIt (c)..."). Again a container hint.
    #[cfg(feature = "arsenic")]
    if p.starts_with(b"StuffIt") {
        return Some(crate::arsenic::Arsenic::NAME);
    }

    // ── 4-byte magics ──────────────────────────────────────────────────

    // zstd: little-endian 0xFD2FB528 → bytes 28 B5 2F FD. RFC 8478 §3.1.1.
    #[cfg(feature = "zstd")]
    if p.starts_with(&[0x28, 0xB5, 0x2F, 0xFD]) {
        return Some(crate::zstd::Zstd::NAME);
    }

    // lz4 frame: little-endian 0x184D2204 → bytes 04 22 4D 18. LZ4 Frame
    // Format §4. (The legacy/skippable-frame magics are not detected.)
    #[cfg(feature = "lz4")]
    if p.starts_with(&[0x04, 0x22, 0x4D, 0x18]) {
        return Some(crate::lz4::frame::LZ4Frame::NAME);
    }

    // ── 3-byte magics ──────────────────────────────────────────────────

    // bzip2: "BZh" (0x42 0x5A 0x68). The 4th byte is the block-size digit
    // '1'..='9'; we accept any prefix that is at least "BZh".
    #[cfg(feature = "bzip2")]
    if p.starts_with(&[0x42, 0x5A, 0x68]) {
        return Some(crate::bzip2::Bzip2::NAME);
    }

    // ── 2-byte magics ──────────────────────────────────────────────────

    // gzip: 0x1F 0x8B (RFC 1952 §2.3.1, ID1 ID2).
    #[cfg(feature = "gzip")]
    if p.starts_with(&[0x1F, 0x8B]) {
        return Some(crate::gzip::Gzip::NAME);
    }

    // zlib: RFC 1950 §2.2. The header is CMF then FLG. For deflate the
    // compression method (low nibble of CMF) is 8 and CINFO (high nibble) is
    // ≤ 7, giving CMF == 0x78 for the standard 32 KiB window. The two header
    // bytes, read big-endian as CMF*256 + FLG, must be a multiple of 31.
    // Requiring both the 0x78 CMF *and* the %31 checksum keeps this from
    // firing on arbitrary data (only ~1 in 31 of the 0x78-prefixed pairs
    // pass). Checked last because it is the weakest of the magics.
    #[cfg(feature = "zlib")]
    if let (Some(&cmf), Some(&flg)) = (p.first(), p.get(1))
        && cmf == 0x78
        && ((cmf as u16) * 256 + flg as u16).is_multiple_of(31)
    {
        return Some(crate::zlib::Zlib::NAME);
    }

    None
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
    if str_eq(name, "lzma2") && cfg!(feature = "lzma2") {
        return Some("lzma2");
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
    if str_eq(name, "lh2") && cfg!(feature = "lha") {
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
    // Standalone primitives / transforms with no conventional file extension;
    // the codec name doubles as the suffix the CLI appends.
    if str_eq(name, "huffman") && cfg!(feature = "huffman") {
        return Some("huff");
    }
    if str_eq(name, "range") && cfg!(feature = "rangecoder") {
        return Some("range");
    }
    if str_eq(name, "mtf") && cfg!(feature = "mtf") {
        return Some("mtf");
    }
    if str_eq(name, "bwt") && cfg!(feature = "bwt") {
        return Some("bwt");
    }
    if str_eq(name, "crunch") && cfg!(feature = "arc_crunch") {
        return Some("arc");
    }
    if str_eq(name, "squeeze") && cfg!(feature = "arc_squeeze") {
        return Some("sqz");
    }
    if str_eq(name, "squashed") && cfg!(feature = "arc_squash") {
        return Some("arc");
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
        #[cfg(feature = "lzma2")]
        crate::lzma2::Lzma2::NAME,
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
        crate::lha::Lh2::NAME,
        #[cfg(feature = "lha")]
        crate::lha::Lh4::NAME,
        #[cfg(feature = "lha")]
        crate::lha::Lh5::NAME,
        #[cfg(feature = "lha")]
        crate::lha::Lh6::NAME,
        #[cfg(feature = "lha")]
        crate::lha::Lh7::NAME,
        #[cfg(feature = "hpack")]
        crate::hpack::Http2Huffman::NAME,
        #[cfg(feature = "huffman")]
        crate::huffman_codec::Huffman::NAME,
        #[cfg(feature = "rangecoder")]
        crate::rangecoder::RangeCoder::NAME,
        #[cfg(feature = "mtf")]
        crate::mtf::Mtf::NAME,
        #[cfg(feature = "bwt")]
        crate::bwt::Bwt::NAME,
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
        #[cfg(feature = "arc_squash")]
        crate::arc_squash::ArcSquash::NAME,
    ]
}

#[cfg(test)]
mod detect_tests {
    use super::detect;
    #[cfg(feature = "arsenic")]
    use alloc::vec::Vec;

    // Short and arbitrary input never panics and never guesses.
    #[test]
    fn empty_and_short_input_is_none() {
        assert_eq!(detect(&[]), None);
        assert_eq!(detect(&[0x1F]), None); // gzip needs 2 bytes
        assert_eq!(detect(&[0x28, 0xB5]), None); // zstd needs 4 bytes
    }

    #[test]
    fn random_input_is_none() {
        // A spread of bytes that matches no signature.
        assert_eq!(detect(&[0x00, 0x01, 0x02, 0x03, 0x04, 0x05]), None);
        assert_eq!(detect(b"hello, world, this is plain text"), None);
        // 0xFF.. doesn't collide with any magic.
        assert_eq!(detect(&[0xFF; 16]), None);
    }

    #[test]
    #[cfg(feature = "gzip")]
    fn detects_gzip() {
        assert_eq!(detect(&[0x1F, 0x8B, 0x08, 0x00]), Some("gzip"));
    }

    #[test]
    #[cfg(feature = "xz")]
    fn detects_xz() {
        assert_eq!(
            detect(&[0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00, 0x00, 0x04]),
            Some("xz")
        );
    }

    #[test]
    #[cfg(feature = "zstd")]
    fn detects_zstd() {
        assert_eq!(detect(&[0x28, 0xB5, 0x2F, 0xFD, 0x00, 0x00]), Some("zstd"));
    }

    #[test]
    #[cfg(feature = "bzip2")]
    fn detects_bzip2() {
        // "BZh9" — block-size '9'.
        assert_eq!(detect(b"BZh91AY&SY"), Some("bzip2"));
    }

    #[test]
    #[cfg(feature = "lz4")]
    fn detects_lz4_frame() {
        assert_eq!(
            detect(&[0x04, 0x22, 0x4D, 0x18, 0x40, 0x40]),
            Some("lz4-frame")
        );
    }

    #[test]
    #[cfg(feature = "zlib")]
    fn detects_zlib_when_checksum_valid() {
        // 0x78 0x9C: 0x789C = 30876 = 31 * 996, divisible by 31 → valid.
        assert_eq!(detect(&[0x78, 0x9C, 0x00]), Some("zlib"));
        // 0x78 0x01 (no/low compression): 0x7801 = 30721 = 31 * 991 → valid.
        assert_eq!(detect(&[0x78, 0x01]), Some("zlib"));
        // 0x78 0xDA (best compression): 0x78DA = 30938 = 31 * 998 → valid.
        assert_eq!(detect(&[0x78, 0xDA]), Some("zlib"));
    }

    #[test]
    #[cfg(feature = "zlib")]
    fn rejects_zlib_when_checksum_invalid() {
        // 0x78 0x00: 0x7800 = 30720, not divisible by 31 → must NOT match.
        assert_eq!(detect(&[0x78, 0x00, 0x00, 0x00]), None);
        // 0x78 0x9D: 30877, 30877 % 31 == 1 → must NOT match.
        assert_eq!(detect(&[0x78, 0x9D]), None);
    }

    #[test]
    #[cfg(feature = "rar5")]
    fn detects_rar5() {
        // "Rar!\x1A\x07\x01\x00" — RAR 5.0.
        assert_eq!(
            detect(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00]),
            Some("rar5")
        );
    }

    #[test]
    #[cfg(feature = "rar3")]
    fn detects_rar4_era_as_representative() {
        // "Rar!\x1A\x07\x00" — RAR 1.5–4.x → representative rar3.
        assert_eq!(
            detect(&[0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]),
            Some("rar3")
        );
    }

    #[test]
    #[cfg(feature = "arsenic")]
    fn detects_stuffit_classic_container() {
        // "SIT!" + 6 bytes + "rLau".
        let mut buf = Vec::new();
        buf.extend_from_slice(b"SIT!");
        buf.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // bytes 4..10
        buf.extend_from_slice(b"rLau"); // bytes 10..14
        assert_eq!(detect(&buf), Some("arsenic"));

        // "SIT!" without the "rLau" creator tag must NOT match.
        let not_sit = b"SIT!\0\0\0\0\0\0XXXX";
        assert_eq!(detect(not_sit), None);
    }

    #[test]
    #[cfg(feature = "arsenic")]
    fn detects_stuffit5_container() {
        assert_eq!(detect(b"StuffIt (c)1997"), Some("arsenic"));
    }

    // brotli has no magic; an arbitrary brotli-ish first byte must not be
    // mistaken for any format we recognize.
    #[test]
    fn brotli_is_not_detectable() {
        // A typical brotli stream starts with e.g. 0x1B/0x0B/0x21 windows;
        // none collide with a recognized magic.
        assert_eq!(detect(&[0x1B, 0x00, 0x00]), None);
        assert_eq!(detect(&[0x0B, 0x00]), None);
    }
}
