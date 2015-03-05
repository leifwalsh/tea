use std::io;

use super::super::{Key, Block};
use cipher;
use mem;

fn decrypt_chunk(key: &Key, prev: &mut Block, chunk: &[u8]) -> [u8; 8] {
    let input_block = mem::read_block(chunk);
    let mut decrypted_block = cipher::decipher(&key, input_block);
    decrypted_block[0] ^= prev[0];
    decrypted_block[1] ^= prev[1];
    *prev = *input_block;
    *mem::write_block(&decrypted_block)
}

/// Wraps an underlying `std::io::BufRead` so that bytes read get
/// decrypted on the way through.
///
/// # Example:
/// ```.ignore
/// use std::fs::File;
/// use std::io::{BufReader, Read};
/// use tea::io::Reader;
///
/// let f = File::open("foo.txt").ok().unwrap();
/// let mut decrypt_f = Reader::new(BufReader::new(f),
///                                 [1, 2, 3, 4], [5, 6]);
/// let mut s = "".to_string();
/// decrypt_f.read_to_string(&mut s).ok().unwrap();
/// ```
pub struct Reader<R: io::BufRead> {
    source: R,
    key: Key,
    prev: Block,
    buf: Vec<u8>,
}

impl<R: io::BufRead> Reader<R> {

    /// Wraps `source` in a `Reader` that will decrypt with the given
    /// `key` and `iv` (initialization vector).
    pub fn new(source: R, key: Key, iv: Block) -> Reader<R> {
        Reader{
            source: source,
            key: key,
            prev: iv,
            buf: Vec::with_capacity(8),
        }
    }

}

impl<R: io::BufRead> io::Read for Reader<R> {

    /// Reads from `source`, decrypts the data, and writes the result
    /// to `buf`.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut pos = 0;
        while pos < buf.len() {
            {
                let encrypted_bytes = try!(self.source.fill_buf());
                if encrypted_bytes.is_empty() {
                    if !self.buf.is_empty() {
                        // Handle padding bytes.
                        let real_bytes = self.buf.len() - self.buf[self.buf.len()-1] as usize;

                        // Weird scoping follows.  We want to discard
                        // the lifetime where real_slice is borrowing
                        // from self.buf so we can truncate it, but we
                        // still want to know what n is, so we have to
                        // let that value escape.
                        let n = {
                            let real_slice = &self.buf[..real_bytes];
                            let n2 = buf[pos..].clone_from_slice(real_slice);
                            pos += n2;
                            n2
                        };
                        if n == real_bytes {
                            self.buf.truncate(0);
                        } else {
                            self.buf = self.buf.split_off(n);
                        }
                    }
                    return Ok(pos);
                } else {
                    assert!(encrypted_bytes.len() >= 8,
                            "not enough bytes to decrypt, encrypted data should be a multiple of 8 bytes but we got {}", encrypted_bytes.len());

                    if !self.buf.is_empty() {
                        let n = buf[pos..].clone_from_slice(&self.buf);
                        pos += n;
                        if n == self.buf.len() {
                            self.buf.truncate(0);
                        } else {
                            self.buf = self.buf.split_off(n);
                            return Ok(pos);
                        }
                    }

                    self.buf.push_all(&decrypt_chunk(&self.key, &mut self.prev, &encrypted_bytes[0..8]));
                }
            }
            self.source.consume(8);
        }
        Ok(pos)
    }

}

#[test]
fn it_works() {
    use std::io::{Read, Write};
    use super::Writer;

    for chunk_size in 1..65 {
        let input: Vec<u8> = (0u8..128).collect();
        let mut writer = Writer::new(io::Cursor::new(Vec::with_capacity(128)),
                                     [1, 2, 3, 4], [5, 6]);
        for chunk in input.chunks(chunk_size) {
            assert_eq!(writer.write(chunk).ok().unwrap(), chunk.len());
        }

        let crypted = writer.close().ok().unwrap().into_inner();
        assert!(crypted.len() == input.len() + 8);
        assert!(crypted != input);

        let mut reader = Reader::new(io::Cursor::new(crypted),
                                     [1, 2, 3, 4], [5, 6]);
        let mut decrypted: Vec<u8> = Vec::new();
        assert!(reader.read_to_end(&mut decrypted).is_ok());
        assert_eq!(decrypted, input);
    }
}
