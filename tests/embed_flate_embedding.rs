//! The codecs built in `const` context, owning their table, and drained
//! through their output between pieces.

#![cfg(all(feature = "embed", feature = "gzip", feature = "zlib"))]

use std::sync::Mutex;

use compcol::embed::flate::*;

/// An output of the caller's, buildable in `const` context: counts.
struct Count(u64);

impl Output for Count {
    const VERIFY: bool = false;

    fn put<C: Checksum>(&mut self, _: u8, _: &mut C) -> Result<(), Error> {
        self.0 += 1;
        Ok(())
    }

    fn copy<C: Checksum>(&mut self, dist: usize, len: usize, _: &mut C) -> Result<(), Error> {
        if dist as u64 > self.0 {
            return Err(Error::InvalidDistance);
        }
        self.0 += len as u64;
        Ok(())
    }

    fn flush<C: Checksum>(&mut self, _: &mut C) -> Result<(), Error> {
        Ok(())
    }

    fn written(&self) -> u64 {
        self.0
    }
}

/// Built at compile time, as firmware would in a `static`.
static DECOMPRESSOR: Mutex<Decompressor<Count, Gzip>> = Mutex::new(Decompressor::new(Count(0)));

static COMPRESSOR: Mutex<Compressor<'static, Count, Zlib, [u16; 1024]>> =
    Mutex::new(Compressor::new(Count(0), [0; 1024]));

fn data() -> Vec<u8> {
    (0..20_000u32)
        .flat_map(|i| format!("{} ", i % 997).into_bytes())
        .collect()
}

#[test]
fn owned_table_compresses_as_a_borrowed_one() {
    let data = data();
    let mut owned_out = vec![0; data.len() + 64];
    let mut compressor = Compressor::<_, Gzip, _>::new(Buffer::new(&mut owned_out), [0u16; 4096]);
    compressor.write(&data).unwrap();
    let owned_len = compressor.finish().unwrap() as usize;

    let mut table = [0u16; 4096];
    let mut borrowed_out = vec![0; data.len() + 64];
    let borrowed_len = gzip(&data, &mut table, Buffer::new(&mut borrowed_out)).unwrap() as usize;
    assert_eq!(owned_out[..owned_len], borrowed_out[..borrowed_len]);

    let mut back = vec![0; data.len()];
    let len = gunzip(&owned_out[..owned_len], Buffer::new(&mut back)).unwrap() as usize;
    assert_eq!(back[..len], data[..]);
}

#[test]
fn statics_work_and_are_reusable() {
    let data = data();
    let mut table = [0u16; 1024];
    let mut gz = vec![0; data.len() + 64];
    let gz_len = gzip(&data, &mut table, Buffer::new(&mut gz)).unwrap() as usize;
    let mut zl = vec![0; data.len() + 64];
    let zl_len = zlib(&data, &mut table, Buffer::new(&mut zl)).unwrap() as usize;

    // Twice, to check both start again from where their output is.
    for _ in 0..2 {
        let mut decompressor = DECOMPRESSOR.lock().unwrap();
        let before = decompressor.output().written();
        for piece in gz[..gz_len].chunks(100) {
            decompressor.write(piece).unwrap();
        }
        assert_eq!(decompressor.finish().unwrap(), data.len() as u64);
        assert_eq!(decompressor.output().written() - before, data.len() as u64);

        let mut compressor = COMPRESSOR.lock().unwrap();
        compressor.write(&data).unwrap();
        assert_eq!(compressor.finish().unwrap(), zl_len as u64);
    }
}

#[test]
fn output_drained_between_pieces() {
    let data = data();
    let mut table = [0u16; 1024];
    let mut gz = vec![0; data.len() + 64];
    let gz_len = gzip(&data, &mut table, Buffer::new(&mut gz)).unwrap() as usize;

    // A `Buffer` taken out of the decompressor after each piece, and put
    // back empty: the decompressor only needs `written` to go on.
    let mut out = vec![0; data.len()];
    let mut decompressor = Decompressor::<_, Gzip>::new(Buffer::new(&mut out));
    let mut seen = 0;
    for piece in gz[..gz_len].chunks(4096) {
        decompressor.write(piece).unwrap();
        let filled = decompressor.output().filled().len();
        assert!(filled >= seen);
        seen = filled;
        let _ = decompressor.output_mut();
    }
    assert_eq!(decompressor.finish().unwrap(), data.len() as u64);
    assert_eq!(out, data);
}
