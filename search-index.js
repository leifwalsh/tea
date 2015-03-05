var searchIndex = {};
searchIndex['tea'] = {"items":[[0,"","tea","Implements the XTEA block cipher, whose reference source is public\ndomain.  This code is also public domain."],[0,"cipher","","Implements the basic XTEA cipher routines as described in the\npaper (http://en.wikipedia.org/wiki/XTEA).  These functions only\ndeal with a single 64-bit block of data at a time."],[5,"encipher","tea::cipher","Encrypts 64 bits of `input` using the `key`."],[5,"decipher","","Decrypts 64 bits of `input` using the `key`."],[0,"io","tea","Bundles the `cipher` module into a CBC-mode block cipher, which\nwraps and implements the `std::io::Read` and `std::io::Write`\ninterfaces."],[3,"Reader","tea::io","Wraps an underlying `std::io::BufRead` so that bytes read get\ndecrypted on the way through."],[3,"Writer","","Wraps an underlying `std::io::Write` so that bytes written get\nencrypted and passed through.  You must call `close()` when\nfinished writing to append the padding bytes."],[11,"new","","Wraps `source` in a `Reader` that will decrypt with the given\n`key` and `iv` (initialization vector).",0],[11,"read","","Reads from `source`, decrypts the data, and writes the result\nto `buf`.",0],[11,"new","","Wraps `sink` in a `Writer` that will encrypt with the given\n`key` and `iv` (initialization vector).",1],[11,"close","","Writes the final padding bytes according to PKCS#7, destroys\nthe encrypting wrapper, and returns the underlying\n`std::io::Write` object.",1],[11,"write","","Encrypts the bytes in `buf` and passes them through to the\nunderlying `std::io::Write`.  If there are not an exact\nmultiple of 8 bytes available, the remaining ones will be\ncached until more data is written or the `Writer` is closed.",1],[11,"flush","","Passes the flush call through to the underlying\n`std::io::Write` object, but only if the internal buffer is\nclear.  If we have some cached bytes that are waiting for a\nfull block before they can be encrypted, it is an error to try\nto call `flush()`.",1],[6,"Key","tea","A key is 128 bits.  We don't seem to need SIMD anywhere so it's\njust an array."],[6,"Block","","XTEA uses 64-bit blocks; for simplicity and to match the reference\nsource, we use an array here too."]],"paths":[[3,"Reader"],[3,"Writer"]]};
initSearch(searchIndex);