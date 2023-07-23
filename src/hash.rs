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

    pub use argon2;

    use crate::{size::SIZE_32, Error, Result};

    /// Argon2id
    ///
    /// Algorithm: Argon2id
    ///
    /// Version: 19 (0x13)
    ///
    /// Memory cost: 19456
    ///
    /// Time(number of iterations): 2
    ///
    /// Parallelism: 1
    ///
    /// Length: 32-byte
    ///
    /// # Example
    ///```
    /// let password = b"hello 0123 password";
    ///
    /// let salt = xck::rand::gen_16();
    ///
    /// let hash = xck::hash::password_hash::argon2id(password, &salt).unwrap();
    ///
    /// println!("{:?}",hash);
    ///```
    pub fn argon2id(password: impl AsRef<[u8]>, salt: impl AsRef<[u8]>) -> Result<[u8; SIZE_32]> {
        let mut buf = [0u8; SIZE_32];

        argon2::Argon2::default()
            .hash_password_into(password.as_ref(), salt.as_ref(), &mut buf)
            .map_err(|err| Error::new(err.to_string()))?;
        Ok(buf)
    }

    /// Argon2id With Secret
    ///
    /// Algorithm: Argon2id
    ///
    /// Version: 19 (0x13)
    ///
    /// Memory cost: 19456
    ///
    /// Time(number of iterations): 2
    ///
    /// Parallelism: 1
    ///
    /// Length: 32-byte
    ///
    /// # Example
    ///```
    /// let password = b"hello 0123 password";
    ///
    /// let salt = xck::rand::gen_16();
    ///
    /// let secret = xck::rand::gen_32();
    ///
    /// let hash = xck::hash::password_hash::argon2id_with_secret(password, &salt, &secret).unwrap();
    ///
    /// println!("{:?}",hash);
    ///```
    pub fn argon2id_with_secret(
        password: impl AsRef<[u8]>,
        salt: impl AsRef<[u8]>,
        secret: impl AsRef<[u8]>,
    ) -> Result<[u8; SIZE_32]> {
        let mut buf = [0u8; SIZE_32];

        argon2::Argon2::new_with_secret(
            secret.as_ref(),
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2::Params::default(),
        )
        .map_err(|err| Error::new(err.to_string()))?
        .hash_password_into(password.as_ref(), salt.as_ref(), &mut buf)
        .map_err(|err| Error::new(err.to_string()))?;

        Ok(buf)
    }
}
