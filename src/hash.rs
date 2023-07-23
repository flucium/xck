use blake3::Hasher as Blake3;

use sha2::{digest::Digest, Sha256, Sha512, Sha512_256};

use crate::size::{SIZE_32, SIZE_64};

/// BLAKE3 KDF default context.
pub const BLAKE3_DEFAULT_CONTEXT: &str = "XCK VERSION 0.0.1 BLAKE3 DEFAULT CONTEXT";

/// BLAKE3 Message authentication code.
///
/// # Example
/// ```
/// let key = xck::hash::blake3_kdf(xck::hash::BLAKE3_DEFAULT_CONTEXT,b"key material");
///
/// let mac = xck::hash::blake3_mac(&key,b"message");
///
/// println!("{:?}",mac);
/// ```
pub fn blake3_mac(key: &[u8; SIZE_32], message: &[u8]) -> [u8; SIZE_32] {
    blake3::keyed_hash(key, message).into()
}

/// BLAKE3 Key derivation function.
///
/// # Example
/// ```
/// let key = xck::hash::blake3_kdf(xck::hash::BLAKE3_DEFAULT_CONTEXT,b"key material");
///
/// println!("{:?}",key);
/// ```
pub fn blake3_kdf(context: &str, material: &[u8]) -> [u8; SIZE_32] {
    blake3::derive_key(context, material).into()
}

/// BLAKE3 Extend.
///
/// # Example
/// ```
/// let buffer:[u8;64] = [0u8;64];
///
/// xck::hash::blake3_xof(b"hello",&mut buffer);
///
/// println!("{:?}",digest);
/// ```
pub fn blake3_xof(bytes: &[u8], dst: &mut [u8]) {
    Blake3::new().update(bytes).finalize_xof().fill(dst);
}

/// BLAKE3 Regular hash digest.
///
/// # Example
/// ```
/// let digest = xck::hash::blake3(b"hello");
///
/// println!("{:?}",digest);
/// ```
pub fn blake3(bytes: &[u8]) -> [u8; SIZE_32] {
    blake3::hash(bytes).into()
}

/// SHA512/256 hash digest.
///
/// # Example
/// ```
/// let digest = xck::hash::sha512_256(b"hello");
///
/// println!("{:?}",digest);
/// ```
pub fn sha512_256(bytes: &[u8]) -> [u8; SIZE_32] {
    Sha512_256::digest(bytes).into()
}

/// SHA512 hash digest.
///
/// # Example
/// ```
/// let digest = xck::hash::sha512(b"hello");
///
/// println!("{:?}",digest);
/// ```
pub fn sha512(bytes: &[u8]) -> [u8; SIZE_64] {
    Sha512::digest(bytes).into()
}

/// SHA256 hash digest.
///
/// # Example
/// ```
/// let digest = xck::hash::sha256(b"hello");
///
/// println!("{:?}",digest);
/// ```
pub fn sha256(bytes: &[u8]) -> [u8; SIZE_32] {
    Sha256::digest(bytes).into()
}

/// # WARNING
/// This is in the development and even PHC-string is not supported.
pub mod password_hash {
    use crate::{
        size::{SIZE_16, SIZE_32},
        Error, Result,
    };
    // use argon2::{
    //     password_hash::{PasswordHash, SaltString},
    //     Argon2, Params as Argon2Params, PasswordHasher,
    // };
    use argon2::Argon2;

    pub fn argon2id(password: &[u8], salt: &[u8; SIZE_16]) -> Result<[u8; SIZE_32]> {
        let mut buf = [0u8; SIZE_32];

        Argon2::default()
            .hash_password_into(password, salt, &mut buf)
            .map_err(|err| Error::new(err.to_string()))?;

        Ok(buf)
    }
}
