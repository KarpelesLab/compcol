//! Fixed data tables for the Arsenic (StuffIt 5 method 15) codec.
//!
//! These are wire-format constants required for bit-exact decoding. They
//! are maintainer-sanctioned interoperability data embedded verbatim from
//! the project's staged tables (`tables/arithmetic_models.csv` and
//! `tables/randomization_table.csv`).

/// Parameters of one adaptive arithmetic model: the inclusive value range
/// `[first, last]`, the per-symbol frequency increment, and the rescale
/// frequency limit. Each symbol's frequency initialises to `increment`.
#[derive(Clone, Copy)]
pub(crate) struct ModelParams {
    pub first: u16,
    pub last: u16,
    pub increment: u32,
    pub limit: u32,
}

impl ModelParams {
    #[inline]
    pub(crate) const fn num_symbols(&self) -> usize {
        (self.last - self.first + 1) as usize
    }
}

/// The single-bit "initial" model: signature bytes, header fields, all
/// per-block flags/indices, and the trailing CRC bits.
pub(crate) const INITIAL_MODEL: ModelParams = ModelParams {
    first: 0,
    last: 1,
    increment: 1,
    limit: 256,
};

/// The selector model (values 0..=10): drives the MTF/RLE token stream.
pub(crate) const SELECTOR_MODEL: ModelParams = ModelParams {
    first: 0,
    last: 10,
    increment: 8,
    limit: 1024,
};

/// The seven MTF models. Selector `s` in 3..=9 escapes into
/// `MTF_MODELS[s - 3]`, whose value range supplies the MTF index.
pub(crate) const MTF_MODELS: [ModelParams; 7] = [
    ModelParams {
        first: 2,
        last: 3,
        increment: 8,
        limit: 1024,
    },
    ModelParams {
        first: 4,
        last: 7,
        increment: 4,
        limit: 1024,
    },
    ModelParams {
        first: 8,
        last: 15,
        increment: 4,
        limit: 1024,
    },
    ModelParams {
        first: 16,
        last: 31,
        increment: 4,
        limit: 1024,
    },
    ModelParams {
        first: 32,
        last: 63,
        increment: 2,
        limit: 1024,
    },
    ModelParams {
        first: 64,
        last: 127,
        increment: 2,
        limit: 1024,
    },
    ModelParams {
        first: 128,
        last: 255,
        increment: 1,
        limit: 1024,
    },
];

/// De-randomization spacing table: 256 unsigned 16-bit values, indexed
/// cyclically (`& 255`). Embedded verbatim from the staged
/// `randomization_table.csv`.
pub(crate) const RAND_TABLE: [u16; 256] = [
    238, 86, 248, 195, 157, 159, 174, 44, 173, 205, 36, 157, 166, 257, 24, 185, 161, 130, 117, 233,
    159, 85, 102, 106, 134, 113, 220, 132, 86, 150, 86, 161, 132, 120, 183, 50, 106, 3, 227, 2, 17,
    257, 8, 68, 131, 256, 67, 227, 28, 240, 134, 106, 107, 15, 3, 45, 134, 23, 123, 16, 246, 128,
    120, 122, 161, 225, 239, 140, 246, 135, 75, 167, 226, 119, 250, 184, 129, 238, 119, 192, 157,
    41, 32, 39, 113, 18, 224, 107, 209, 124, 10, 137, 125, 135, 196, 257, 193, 49, 175, 56, 3, 104,
    27, 118, 121, 63, 219, 199, 27, 54, 123, 226, 99, 129, 238, 12, 99, 139, 120, 56, 151, 155,
    215, 143, 221, 242, 163, 119, 140, 195, 57, 32, 179, 18, 17, 14, 23, 66, 128, 44, 196, 146, 89,
    200, 219, 64, 118, 100, 180, 85, 26, 158, 254, 95, 6, 60, 65, 239, 212, 170, 152, 41, 205, 31,
    2, 168, 135, 210, 160, 147, 152, 239, 12, 67, 237, 157, 194, 235, 129, 233, 100, 35, 104, 30,
    37, 87, 222, 154, 207, 127, 229, 186, 65, 234, 234, 54, 26, 40, 121, 32, 94, 24, 78, 124, 142,
    88, 122, 239, 145, 2, 147, 187, 86, 161, 73, 27, 121, 146, 243, 88, 79, 82, 156, 2, 119, 175,
    42, 143, 73, 208, 153, 77, 152, 257, 96, 147, 256, 117, 49, 206, 73, 32, 86, 87, 226, 245, 38,
    43, 138, 191, 222, 208, 131, 52, 244, 23,
];
