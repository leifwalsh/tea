#![feature(collections,io)]

//! Implements the XTEA block cipher, whose reference source is public
//! domain.  This code is also public domain.
//!
//! Also implements a CBC-mode block cipher with padding.  I'm not
//! good at crypto so don't use this.

/// A key is 128 bits.  We don't seem to need SIMD anywhere so it's
/// just an array.
pub type Key = [u32; 4];

/// XTEA uses 64-bit blocks; for simplicity and to match the reference
/// source, we use an array here too.
pub type Block = [u32; 2];

pub mod cipher;
pub mod io;
mod mem;
