use crate::size::{SIZE_32, SIZE_64};
use sha2::{digest::Digest, Sha256, Sha512, Sha512_256};

pub const BLAKE3_DEFAULT_CONTEXT: &str = "XCK VERSION 0.0.1 BLAKE3 DEFAULT CONTEXT";

/// BLAKE3 ...
pub fn blake3(bytes: &[u8]) -> [u8; SIZE_32] {
    blake3::hash(bytes).into()
}

/// BLAKE3 XOF ...
pub fn blake3_xof(bytes: &[u8], dst: &mut [u8]) {
    blake3::Hasher::new().update(bytes).finalize_xof().fill(dst);
}

/// BLAKE3 KDF ...
pub fn blake3_kdf(context: &str, material: &[u8]) -> [u8; SIZE_32] {
    blake3::derive_key(context, material).into()
}

/// BLAKE3 MAC ...
pub fn blake3_mac(key: [u8; SIZE_32], message: &[u8]) -> [u8; SIZE_32] {
    blake3::keyed_hash(&key, message).into()
}

/// SHA256 ...
pub fn sha256(bytes: &[u8]) -> [u8; SIZE_32] {
    Sha256::digest(bytes).into()
}

/// SHA512 ...
pub fn sha512(bytes: &[u8]) -> [u8; SIZE_64] {
    Sha512::digest(bytes).into()
}

/// SHA512/256 ...
pub fn sha512_256(bytes: &[u8]) -> [u8; SIZE_32] {
    Sha512_256::digest(bytes).into()
}
