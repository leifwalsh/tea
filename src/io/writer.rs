use std::io;

use super::super::{Key, Block};
use cipher;
use mem;

fn encrypt_chunk<'a>(key: &Key, prev: &'a mut Block, chunk: &[u8]) -> &'a [u8; 8] {
    let input_block = {
        let mut mut_input_block = *mem::read_block(chunk);
        mut_input_block[0] ^= prev[0];
        mut_input_block[1] ^= prev[1];
        mut_input_block
    };
    *prev = cipher::encipher(&key, &input_block);
    mem::write_block(prev)
}

/// Wraps an underlying `std::io::Write` so that bytes written get
/// encrypted and passed through.  You must call `close()` when
/// finished writing to append the padding bytes.
///
/// # Example:
/// ```.ignore
/// use std::fs::File;
/// use std::io::Write;
/// use tea::io::Writer;
///
/// let f = File::create("foo.txt").ok().unwrap();
/// let mut crypt_f = Writer::new(f, [1, 2, 3, 4], [5, 6]);
/// crypt_f.write_all(b"Hello, world!").ok().unwrap();
/// crypt_f.close().ok().unwrap();
/// ```
pub struct Writer<W: io::Write> {
    sink: W,
    key: Key,
    prev: Block,
    buf: Vec<u8>,
    enc_buf: Vec<u8>,
}

impl<W: io::Write> Writer<W> {

    /// Wraps `sink` in a `Writer` that will encrypt with the given
    /// `key` and `iv` (initialization vector).
    pub fn new(sink: W, key: Key, iv: Block) -> Writer<W> {
        Writer{
            sink: sink,
            key: key,
            prev: iv,
            buf: Vec::with_capacity(8),
            enc_buf: Vec::with_capacity(8),
        }
    }

    /// Writes the final padding bytes according to PKCS#7, destroys
    /// the encrypting wrapper, and returns the underlying
    /// `std::io::Write` object.
    pub fn close(mut self) -> io::Result<W> {
        if !try!(self.flush_enc_buf()) {
            return Err(io::Error::new(io::ErrorKind::Other, "couldn't flush encrypted bytes to sink",
                                      Some(format!("sink couldn't write the last {} bytes that were already encoded", self.enc_buf.len()))));
        }
        self.enc_buf.truncate(0);

        let pad_byte = 8 - self.buf.len() as u8;
        self.buf.resize(8, pad_byte);
        let written = try!(self.sink.write(encrypt_chunk(&self.key, &mut self.prev, &self.buf)));
        if written != 8 {
            return Err(io::Error::new(io::ErrorKind::Other, "couldn't write final 8 bytes to sink",
                                      Some(format!("sink only accepted {} bytes, can't close this writer", written))));
        }
        self.buf.truncate(0);
        try!(self.sink.flush());
        Ok(self.sink)
    }

    // Flushes the buffer of encrypted data.  Returns Ok(true) if
    // everything's ok, Ok(false) if we couldn't write everything and
    // should stop.
    fn flush_enc_buf(&mut self) -> io::Result<bool> {
        let n = try!(self.sink.write(&self.enc_buf));
        if n < self.enc_buf.len() {
            let rest = self.enc_buf.split_off(n);
            self.enc_buf = rest;
            Ok(false)
        } else {
            self.enc_buf.truncate(0);
            Ok(true)
        }
    }
}

impl<W: io::Write> io::Write for Writer<W> {

    /// Encrypts the bytes in `buf` and passes them through to the
    /// underlying `std::io::Write`.  If there are not an exact
    /// multiple of 8 bytes available, the remaining ones will be
    /// cached until more data is written or the `Writer` is closed.
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if !self.enc_buf.is_empty() {
            if !try!(self.flush_enc_buf()) {
                return Ok(0);
            }
        }

        if buf.is_empty() {
            return Ok(0);
        }

        let mut written: usize = 0;

        if !self.buf.is_empty() {
            let remaining = 8 - self.buf.len();
            self.buf.push_all(&buf[..remaining]);
            written += remaining;

            self.enc_buf.push_all(encrypt_chunk(&self.key, &mut self.prev, &self.buf));
            self.buf.truncate(0);

            if !try!(self.flush_enc_buf()) {
                return Ok(written);
            }
        }

        for chunk in buf[written..].chunks(8) {
            if chunk.len() < 8 {
                self.buf.push_all(chunk);
                written += chunk.len();
                break;
            }

            self.enc_buf.push_all(encrypt_chunk(&self.key, &mut self.prev, chunk));
            written += 8;

            if !try!(self.flush_enc_buf()) {
                return Ok(written);
            }
        }

        Ok(written)
    }

    /// Passes the flush call through to the underlying
    /// `std::io::Write` object, but only if the internal buffer is
    /// clear.  If we have some cached bytes that are waiting for a
    /// full block before they can be encrypted, it is an error to try
    /// to call `flush()`.
    fn flush(&mut self) -> io::Result<()> {
        try!(self.flush_enc_buf());

        if self.buf.is_empty() {
            self.sink.flush()
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "can't flush when not on a 64-bit block boundary",
                               Some(format!("we have {} plaintext bytes that we can't encrypt until a full block is done", self.buf.len()))))
        }
    }

}

#[test]
fn it_works() {
    use std::io::Write;

    let input: Vec<u8> = (0u8..128).collect();
    let mut writer = Writer::new(io::Cursor::new(Vec::with_capacity(128)),
                                 [1, 2, 3, 4], [5, 6]);
    for chunk in input.chunks(16) {
        assert_eq!(writer.write(chunk).ok().unwrap(), 16);
    }

    let result = writer.close().ok().unwrap().into_inner();
    assert!(result.len() == input.len() + 8);
    assert!(result != input)
}
