//! Memory twiddling utilities, so far just for reinterpreting between
//! [u8] and Block.

use super::Block;
use std::mem;

/// Interprets an 8-byte `[u8]` array as a `Block`.
pub fn read_block<'a>(chunk: &'a [u8]) -> &'a Block {
    debug_assert_eq!(chunk.len(), 8);
    unsafe { mem::transmute(chunk.as_ptr() as *const [u8; 8]) }
}

/// Interprets a `Block` as an 8-byte `[u8]` array.
pub fn write_block<'a>(block: &'a Block) -> &'a [u8; 8] {
    unsafe { mem::transmute(block) }
}
