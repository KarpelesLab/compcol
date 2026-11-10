//! Shared strict decode driver for the fuzz targets.
//!
//! The older `decoder_*` targets `break` out of their loop when a call
//! reports `consumed == 0 && written == 0`, which silently turns a decoder
//! stall (the caller of a standard decode loop would spin forever) into a
//! clean exit. This driver does the opposite: a no-progress call is retried
//! once with identical arguments, and if the decoder again makes no progress
//! the target panics, so stalls are findings.
//!
//! Every way out of [`drive`] is one of:
//!   * `Status::StreamEnd`            -> [`Outcome::End`]
//!   * `Err(_)`                       -> [`Outcome::Err`]
//!   * the driver's own step bound    -> [`Outcome::StepBound`]
//!   * the caller's sink refusing more output -> [`Outcome::SinkFull`]
//!   * a panic (stall or a broken `Progress`).
#![allow(dead_code)]

use compcol::{Decoder, Error, Status};

/// How a [`drive`] run ended.
#[derive(Debug)]
pub enum Outcome {
    /// The decoder reported `Status::StreamEnd`.
    End,
    /// The decoder returned an error.
    Err(Error),
    /// The driver gave up after `max_steps` calls (not a decoder verdict).
    StepBound,
    /// The sink asked to stop (not a decoder verdict).
    SinkFull,
}

/// Tiny xorshift generator so a couple of selector bytes can drive a whole
/// sequence of chunk sizes deterministically.
pub struct Rng(u32);

impl Rng {
    pub fn new(seed: u32) -> Self {
        Rng(seed | 1)
    }
    pub fn next(&mut self) -> u32 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 17;
        x ^= x << 5;
        self.0 = x;
        x
    }
}

/// Input-chunk / output-buffer size policy for one run.
pub struct Sizes {
    pub in_max: usize,
    pub out_max: usize,
    /// `None`: always offer exactly `in_max` / `out_max`. `Some`: draw every
    /// step's sizes from `1..=max`.
    pub rng: Option<Rng>,
}

impl Sizes {
    pub fn fixed(in_max: usize, out_max: usize) -> Self {
        Sizes {
            in_max: in_max.max(1),
            out_max: out_max.max(1),
            rng: None,
        }
    }

    /// Build a policy from two selector bytes. The low nibbles index the size
    /// tables; bit 7 of `a` switches on per-step variation.
    pub fn from_bytes(a: u8, b: u8) -> Self {
        const IN: [usize; 16] = [
            1,
            2,
            3,
            4,
            5,
            7,
            8,
            13,
            16,
            61,
            256,
            1021,
            4096,
            65536,
            usize::MAX,
            usize::MAX,
        ];
        const OUT: [usize; 16] = [
            1, 2, 3, 4, 5, 7, 8, 16, 61, 255, 256, 1021, 4096, 32768, 65536, 70001,
        ];
        let in_max = IN[(a & 15) as usize];
        let out_max = OUT[(b & 15) as usize];
        let rng = (a & 0x80 != 0).then(|| Rng::new(u32::from(a) << 8 | u32::from(b)));
        Sizes {
            in_max,
            out_max,
            rng,
        }
    }

    fn next(&mut self) -> (usize, usize) {
        match &mut self.rng {
            None => (self.in_max, self.out_max),
            Some(r) => {
                let i = 1 + (r.next() as usize) % self.in_max.min(1 << 16);
                let o = 1 + (r.next() as usize) % self.out_max;
                (i, o)
            }
        }
    }
}

/// Drive `dec` over `data`, then `finish` it.
///
/// `sink` receives every produced slice and returns `false` to stop the run.
/// `what` only labels panic messages.
///
/// Panics (= fuzz findings):
///   * `Progress` claims more than the slices it was given;
///   * `decode` returns `OutputFull` with `consumed == 0 && written == 0`
///     twice in a row for the same non-empty input and non-empty output;
///   * `finish` returns a non-`StreamEnd` status with `written == 0` twice in
///     a row for the same non-empty output.
pub fn drive<D: Decoder + ?Sized>(
    what: &str,
    dec: &mut D,
    data: &[u8],
    mut sizes: Sizes,
    max_steps: usize,
    mut sink: impl FnMut(&[u8]) -> bool,
) -> Outcome {
    let mut out = vec![0u8; sizes.out_max];
    let mut pos = 0usize;
    let mut steps = 0usize;
    // Sizes of the previous call if it made no progress (to repeat it
    // verbatim), and a growing input offer for decoders that answer
    // `InputEmpty` without consuming a short chunk.
    let mut repeat: Option<(usize, usize)> = None;
    let mut grow = 0usize;

    while pos < data.len() {
        steps += 1;
        if steps > max_steps {
            return Outcome::StepBound;
        }
        let (in_n, out_n) = match repeat {
            Some(s) => s,
            None => {
                let (i, o) = sizes.next();
                (i.saturating_add(grow), o)
            }
        };
        let end = pos.saturating_add(in_n).min(data.len());
        let input = &data[pos..end];
        let (p, status) = match dec.decode(input, &mut out[..out_n]) {
            Ok(v) => v,
            Err(e) => return Outcome::Err(e),
        };
        assert!(
            p.consumed <= input.len() && p.written <= out_n,
            "{what}: decode reported consumed={} of {} / written={} of {}",
            p.consumed,
            input.len(),
            p.written,
            out_n
        );
        if !sink(&out[..p.written]) {
            return Outcome::SinkFull;
        }
        pos += p.consumed;
        if status == Status::StreamEnd {
            return Outcome::End;
        }
        if p.consumed != 0 || p.written != 0 {
            repeat = None;
            grow = 0;
            continue;
        }
        match status {
            Status::OutputFull => {
                if repeat.is_some() {
                    panic!(
                        "{what}: decode stall: OutputFull with consumed=0 written=0 twice in a \
                         row (input offered={} at offset {pos} of {}, output buffer={out_n})",
                        input.len(),
                        data.len()
                    );
                }
                repeat = Some((in_n, out_n));
            }
            Status::InputEmpty => {
                repeat = None;
                if end == data.len() {
                    // Wants more input than exists: let `finish` decide.
                    break;
                }
                grow = grow.saturating_mul(2).max(in_n);
            }
            Status::StreamEnd => unreachable!(),
        }
    }

    let mut repeat: Option<usize> = None;
    loop {
        steps += 1;
        if steps > max_steps {
            return Outcome::StepBound;
        }
        let out_n = repeat.unwrap_or_else(|| sizes.next().1);
        let (p, status) = match dec.finish(&mut out[..out_n]) {
            Ok(v) => v,
            Err(e) => return Outcome::Err(e),
        };
        assert!(
            p.written <= out_n,
            "{what}: finish reported written={} of {out_n}",
            p.written
        );
        if !sink(&out[..p.written]) {
            return Outcome::SinkFull;
        }
        if status == Status::StreamEnd {
            return Outcome::End;
        }
        if p.written != 0 {
            repeat = None;
            continue;
        }
        if repeat.is_some() {
            panic!(
                "{what}: finish stall: {status:?} with written=0 twice in a row \
                 (output buffer={out_n}, input consumed {pos} of {})",
                data.len()
            );
        }
        repeat = Some(out_n);
    }
}

/// The shape shared by the single-codec `decoder_*` targets that use this
/// driver: whole input in one slice, 64 KiB output buffer, 4096-step bound.
pub fn smoke<D: Decoder>(what: &str, mut dec: D, data: &[u8]) {
    let _ = drive(
        what,
        &mut dec,
        data,
        Sizes::fixed(usize::MAX, 64 * 1024),
        4096,
        |_| true,
    );
}
