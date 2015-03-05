//! Implements the basic XTEA cipher routines as described in the
//! paper (http://en.wikipedia.org/wiki/XTEA).  These functions only
//! deal with a single 64-bit block of data at a time.

static NUM_ROUNDS: u32 = 32;

use super::{Key, Block};

/// Encrypts 64 bits of `input` using the `key`.
///
/// # Example:
/// ```
/// use tea::cipher;
///
/// let key = [5, 6, 7, 8];
/// let plaintext = [128, 256];
/// assert!(cipher::encipher(&key, &plaintext) != plaintext);
/// ```
pub fn encipher(key: &Key, input: &Block) -> Block {
    let [mut v0, mut v1] = *input;
    let delta = 0x9E3779B9;
    let mut sum: u32 = 0;
    for _ in 0..NUM_ROUNDS {
        v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[(sum & 3) as usize]);
        sum += delta;
        v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[((sum>>11) & 3) as usize])
    }
    [v0, v1]
}

/// Decrypts 64 bits of `input` using the `key`.
///
/// # Example:
/// ```
/// use tea::cipher;
///
/// let key = [5, 6, 7, 8];
/// let plaintext = [128, 256];
/// let crypted = cipher::encipher(&key, &plaintext);
/// assert_eq!(cipher::decipher(&key, &crypted), plaintext);
/// ```
pub fn decipher(key: &Key, input: &Block) -> Block {
    let [mut v0, mut v1] = *input;
    let delta = 0x9E3779B9;
    let mut sum = delta * NUM_ROUNDS;
    for _ in 0..NUM_ROUNDS {
        v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[((sum>>11) & 3) as usize]);
        sum -= delta;
        v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[(sum & 3) as usize]);
    }
    [v0, v1]
}

#[test]
fn it_works() {
    let key: Key = [10, 20, 30, 42];
    let plaintext: Block = [300, 400];
    let ciphertext = encipher(&key, &plaintext);
    assert!(plaintext != ciphertext);
    assert_eq!(plaintext, decipher(&key, &ciphertext));
}
