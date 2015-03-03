#![feature(collections,io)]

/// Implements the XTEA block cipher, whose reference source is public
/// domain.  This code is also public domain.
///
/// Also implements a CBC-mode block cipher with padding.  I'm not
/// good at crypto so don't use this.

/// A key is 128 bits.  We don't seem to need SIMD anywhere so it's
/// just an array.
pub type Key = [u32; 4];

/// XTEA uses 64-bit blocks; for simplicity and to match the reference
/// source, we use an array here too.
pub type Block = [u32; 2];

static NUM_ROUNDS: u32 = 32;

/// Encrypts 64 bits of input using the key.
pub fn encipher(key: &Key, input: &Block) -> Block {
    // Reference source:
    // unsigned int i;
    // uint32_t v0=v[0], v1=v[1], sum=0, delta=0x9E3779B9;
    // for (i=0; i < num_rounds; i++) {
    //     v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    //     sum += delta;
    //     v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    // }
    // v[0]=v0; v[1]=v1;
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

/// Decrypts 64 bits of input using the key.
pub fn decipher(key: &Key, input: &Block) -> Block {
    // Reference source:
    // unsigned int i;
    // uint32_t v0=v[0], v1=v[1], delta=0x9E3779B9, sum=delta*num_rounds;
    // for (i=0; i < num_rounds; i++) {
    //     v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + key[(sum>>11) & 3]);
    //     sum -= delta;
    //     v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + key[sum & 3]);
    // }
    // v[0]=v0; v[1]=v1;
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

use std::io;
use std::mem;
use std::ptr;

fn read_block(chunk: &[u8]) -> Block {
    assert_eq!(chunk.len(), 8);
    unsafe {
        let mut block: Block = mem::uninitialized();
        let b0 = block.get_unchecked_mut(0) as *mut u32;
        let input = chunk.get_unchecked(0) as *const u8;
        ptr::copy_nonoverlapping(b0 as *mut u8, input, 8);
        block
    }
}

fn write_block(block: &Block) -> [u8; 8] {
    unsafe { mem::transmute(*block) }
}

/// Adapts encipher and decipher into a block cipher using CBC.
pub struct BlockCipher {
    key: Key,
    prev: Block,
}

impl BlockCipher {

    /// Creates an XTEA BlockCipher with a key and an initialization
    /// vector.
    pub fn new(key: Key, iv: Block) -> BlockCipher {
        BlockCipher{key: key, prev: iv}
    }

    fn encrypt_chunk(&mut self, chunk: &[u8], output: &mut io::Write) {
        let mut input_block: Block = read_block(chunk);
        input_block[0] ^= self.prev[0];
        input_block[1] ^= self.prev[1];
        self.prev = encipher(&self.key, &input_block);
        output.write_all(&write_block(&self.prev)).ok().unwrap();
    }

    /// Reads bytes from `input` until it's consumed, and writes the
    /// encrypted bytes to `output`.  Will pad to an 8-byte boundary.
    pub fn encrypt(&mut self, input: &mut io::BufRead, output: &mut io::Write) {
        let mut consumed;
        loop {
            consumed = 0;
            {
                let bytes = input.fill_buf().ok().unwrap();
                if bytes.len() < 8 {
                    let mut vec = bytes.to_vec();
                    vec.resize(8, 8 - bytes.len() as u8);
                    self.encrypt_chunk(&vec, output);
                    consumed = bytes.len();
                    break;
                }
                for chunk in bytes.chunks(8) {
                    if chunk.len() < 8 {
                        break;
                    }
                    self.encrypt_chunk(&chunk, output);
                    consumed += 8;
                }
            }
            input.consume(consumed);
        }
        input.consume(consumed);
    }

    fn decrypt_chunk(&mut self, chunk: &[u8]) -> [u8; 8] {
        let input_block: Block = read_block(chunk);
        let mut decrypted_block = decipher(&self.key, &input_block);
        decrypted_block[0] ^= self.prev[0];
        decrypted_block[1] ^= self.prev[1];
        self.prev = input_block;
        write_block(&decrypted_block)
    }

    /// Reads encrypted bytes from `input` until it's consumed, and
    /// writes the decrypted bytes to `output`.  If the input needed
    /// to be padded, the result will have trailing zeroes.
    pub fn decrypt(&mut self, input: &mut io::BufRead, output: &mut io::Write) {
        let mut last_chunk: [u8; 8] = [0u8; 8];
        let mut last_chunk_initialized = false;
        loop {
            let mut consumed = 0;
            {
                let bytes = input.fill_buf().ok().unwrap();
                if bytes.len() == 0 {
                    break;
                }
                assert!(bytes.len() >= 8);
                for chunk in bytes.chunks(8) {
                    if chunk.len() < 8 {
                        break;
                    }
                    if last_chunk_initialized {
                        output.write_all(&last_chunk).ok().unwrap();
                    }
                    last_chunk = self.decrypt_chunk(&chunk);
                    last_chunk_initialized = true;
                    consumed += 8;
                }
            };
            input.consume(consumed);
        }
        if last_chunk_initialized {
            let padded = last_chunk[7];
            if padded < 8 {
                output.write_all(&last_chunk[..(8 - padded) as usize]).ok().unwrap();
            }
        }
    }

}

#[test]
fn tea_works() {
    let key: Key = [10, 20, 30, 42];
    let plaintext: Block = [300, 400];
    let ciphertext = encipher(&key, &plaintext);
    assert!(plaintext != ciphertext);
    assert_eq!(plaintext, decipher(&key, &ciphertext));
}

#[test]
fn cipher_works() {
    let mut cipher = BlockCipher::new([123, 456, 789, 1011], [867, 5309]);
    let input: Vec<u8> = (0u8..128).collect();

    let mut crypted_cursor: io::Cursor<Vec<u8>> = io::Cursor::new(Vec::new());
    cipher.encrypt(&mut io::Cursor::new(input.clone()), &mut crypted_cursor);
    let crypted = crypted_cursor.into_inner();

    assert_eq!(input.len() + 8, crypted.len());
    assert!(input != crypted);

    // reset cipher iv
    cipher = BlockCipher::new([123, 456, 789, 1011], [867, 5309]);

    let mut decrypted_cursor: io::Cursor<Vec<u8>> = io::Cursor::new(Vec::new());
    cipher.decrypt(&mut io::Cursor::new(crypted.clone()), &mut decrypted_cursor);
    let decrypted = decrypted_cursor.into_inner();
    assert_eq!(input, decrypted);
}

#[test]
fn cipher_padding() {
    let mut cipher = BlockCipher::new([123, 456, 789, 1011], [867, 5309]);
    let input: Vec<u8> = (0u8..123).collect();

    let mut crypted_cursor: io::Cursor<Vec<u8>> = io::Cursor::new(Vec::new());
    cipher.encrypt(&mut io::Cursor::new(input.clone()), &mut crypted_cursor);
    let crypted = crypted_cursor.into_inner();

    assert_eq!(input.len() + 5, crypted.len());
    assert!(input != crypted);

    // reset cipher iv
    cipher = BlockCipher::new([123, 456, 789, 1011], [867, 5309]);

    let mut decrypted_cursor: io::Cursor<Vec<u8>> = io::Cursor::new(Vec::new());
    cipher.decrypt(&mut io::Cursor::new(crypted.clone()), &mut decrypted_cursor);
    let decrypted = decrypted_cursor.into_inner();
    assert_eq!(input, decrypted);
}
