//! Huff0 / FSE entropy decoding shared by the codecs that carry Yann
//! Collet's entropy stage in their streams: `zstd` (literals and sequence
//! tables) and `lz5` (Lizard's Huffman-coded sub-streams).
//!
//! Crate-private. Each codec uses a part of it, so a build with only one
//! of them enabled leaves some of it unused.
#![allow(dead_code)]

pub(crate) mod bitreader;
pub(crate) mod fse;
pub(crate) mod huffman;
