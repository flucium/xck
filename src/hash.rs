// use std::io;

use blake3::Hasher as Blake3;

use sha2::{digest::Digest, Sha256, Sha512, Sha512_256};

use crate::{
    size::{SIZE_32, SIZE_64},
    // Error, Result,
};


/// BLAKE3 KDF default context.
pub const BLAKE3_DEFAULT_CONTEXT: &str = "XCK VERSION 0.0.1 BLAKE3 DEFAULT CONTEXT";

// const BUFFER_SIZE: usize = 8192;
// const BUFFER_SIZE: usize = 1024;

/*
    BLAKE3
    blake3_mac_from_io(...)...{...}
    blake3_xof_from_io(...)...{...}
    blake3_from_io(...)...{...}
    blake3_mac(...)...{...}
    blake3_kdf(...)...{...}
    blake3_xof(...)...{...}
    blake3(...)...{...}
*/

// BLAKE3 Message authentication code from io reader.
// pub fn blake3_mac_from_io<R>(key: &[u8; SIZE_32], r: &mut R) -> Result<[u8; SIZE_32]>
// where
//     R: io::Read,
// {
//     let mut hasher = Blake3::new_keyed(key);

//     let mut buf = [0u8; BUFFER_SIZE];

//     while r
//         .read(&mut buf)
//         .map_err(|err| Error::new(err.to_string()))?
//         > 0
//     {
//         hasher.update(&buf);
//     }

//     Ok(hasher.finalize().into())
// }

// BLAKE3 Extend hash digest from io reader.
// pub fn blake3_xof_from_io<R>(r: &mut R, dst: &mut [u8]) -> Result<()>
// where
//     R: io::Read,
// {
//     let mut hasher = Blake3::new();

//     let mut buf = [0u8; BUFFER_SIZE];

//     while r
//         .read(&mut buf)
//         .map_err(|err| Error::new( err.to_string()))?
//         > 0
//     {
//         hasher.update(&buf);
//     }

//     hasher.finalize_xof().fill(dst);

//     Ok(())
// }

// BLAKE3 Regular hash digest from io reader.
// pub fn blake3_from_io<R>(r: &mut R) -> Result<[u8; SIZE_32]>
// where
//     R: io::Read,
// {
//     let mut hasher = Blake3::new();

//     let mut buf = [0u8; BUFFER_SIZE];

//     while r
//         .read(&mut buf)
//         .map_err(|err| Error::new(err.to_string()))?
//         > 0
//     {
//         hasher.update(&buf);
//     }

//     Ok(hasher.finalize().into())
// }

/// BLAKE3 Message authentication code.
pub fn blake3_mac(key: &[u8; SIZE_32], message: &[u8]) -> [u8; SIZE_32] {
    blake3::keyed_hash(key, message).into()
}

/// BLAKE3 Key derivation function.
pub fn blake3_kdf(context: &str, material: &[u8]) -> [u8; SIZE_32] {
    blake3::derive_key(context, material).into()
}

/// BLAKE3 Extend hash digest.
pub fn blake3_xof(bytes: &[u8], dst: &mut [u8]) {
    Blake3::new().update(bytes).finalize_xof().fill(dst);
}

/// BLAKE3 Regular hash digest.
pub fn blake3(bytes: &[u8]) -> [u8; SIZE_32] {
    blake3::hash(bytes).into()
}

/*
    SHA2
    sha512_256_from_io(...)...{...}
    sha512_from_io(...)...{...}
    sha256_from_io(...)...{...}
    sha512_256(...)...{...}
    sha512(...)...{...}
    sha256(...)...{...}
*/

// SHA512/256 hash digest from io reader.
// pub fn sha512_256_from_io<R>(r: &mut R) -> Result<[u8; SIZE_32]>
// where
//     R: io::Read,
// {
//     let mut hasher = Sha512_256::new();

//     let mut buf = [0u8; BUFFER_SIZE];

//     while r
//         .read(&mut buf)
//         .map_err(|err| Error::new(err.to_string()))?
//         > 0
//     {
//         hasher.update(buf);
//     }

//     Ok(hasher.finalize().into())
// }

// SHA512 hash digest from io reader.
// pub fn sha512_from_io<R>(r: &mut R) -> Result<[u8; SIZE_64]>
// where
//     R: io::Read,
// {
//     let mut hasher = Sha512::new();

//     let mut buf = [0u8; BUFFER_SIZE];

//     while r
//         .read(&mut buf)
//         .map_err(|err| Error::new(err.to_string()))?
//         > 0
//     {
//         hasher.update(buf);
//     }

//     Ok(hasher.finalize().into())
// }

// SHA256 hash digest from io reader.
// pub fn sha256_from_io<R>(r: &mut R) -> Result<[u8; SIZE_32]>
// where
//     R: io::Read,
// {
//     let mut hasher = Sha256::new();

//     let mut buf = [0u8; BUFFER_SIZE];

//     while r
//         .read(&mut buf)
//         .map_err(|err| Error::new( err.to_string()))?
//         > 0
//     {
//         hasher.update(buf);
//     }

//     Ok(hasher.finalize().into())
// }

/// SHA512/256 hash digest.
pub fn sha512_256(bytes: &[u8]) -> [u8; SIZE_32] {
    Sha512_256::digest(bytes).into()
}

/// SHA512 hash digest.
pub fn sha512(bytes: &[u8]) -> [u8; SIZE_64] {
    Sha512::digest(bytes).into()
}

/// SHA256 hash digest.
pub fn sha256(bytes: &[u8]) -> [u8; SIZE_32] {
    Sha256::digest(bytes).into()
}
