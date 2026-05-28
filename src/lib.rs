//! `compcol` — a collection of pure-Rust, `no_std`, 100% safe compression
//! algorithms behind a uniform streaming trait.
//!
//! Each algorithm sits behind its own Cargo feature so downstream crates
//! only pay for what they use. An optional [`factory`] module provides
//! runtime by-name lookup when the `factory` (and thus `alloc`) feature is
//! enabled.
//!
//! See [`Encoder`], [`Decoder`], and [`Algorithm`] for the contract every
//! algorithm in this crate implements.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod error;
mod traits;

pub use error::Error;
pub use traits::{Algorithm, Decoder, Encoder, Progress};

#[cfg(feature = "rle")]
pub mod rle;

#[cfg(feature = "factory")]
pub mod factory;
