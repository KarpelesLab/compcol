//! Shared LZMA2 chunk codec (range coder + LZ window + chunk LZMA payload).
//!
//! These submodules implement the LZMA payload encode/decode used inside
//! LZMA2 compressed chunks. They are reused by both the `.xz` container
//! ([`crate::xz`]) and the raw LZMA2 decoder ([`crate::lzma2`]) so neither
//! feature has to depend on the other. Crate-internal; not part of the
//! public API.

pub(crate) mod lzma2_decoder;

// The LZMA payload *encoder* is only needed by the `.xz` container encoder
// and by round-trip tests; a raw `lzma2`-only build (decode-only) would
// otherwise carry it as dead code.
#[cfg(any(feature = "xz", test))]
pub(crate) mod lzma2_encoder;
