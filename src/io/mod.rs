//! Bundles the `cipher` module into a CBC-mode block cipher, which
//! wraps and implements the `std::io::Read` and `std::io::Write`
//! interfaces.
//!
//! # Example:
//! ```
//! use std::fs;
//! use std::io::{BufReader, Read, Write};
//! use tea::io::{Reader, Writer};
//!
//! let tmp_dir = fs::TempDir::new("tea-reader-test-0").ok().unwrap();
//! let filename = tmp_dir.path().join("foo.txt");
//!
//! {
//!     let f = fs::File::create(&filename).ok().unwrap();
//!     let mut crypt_f = Writer::new(f, [1, 2, 3, 4], [5, 6]);
//!     crypt_f.write_all(b"Hello, world!").ok().unwrap();
//!     crypt_f.close().ok().unwrap();
//! }
//! {
//!     let f = fs::File::open(&filename).ok().unwrap();
//!     let mut decrypt_f = Reader::new(BufReader::new(f), [1, 2, 3, 4], [5, 6]);
//!     let mut s: String = "".to_string();
//!     decrypt_f.read_to_string(&mut s).ok().unwrap();
//!     assert_eq!("Hello, world!", s);
//! }
//! ```

pub use self::reader::Reader;
pub use self::writer::Writer;

mod reader;
mod writer;
