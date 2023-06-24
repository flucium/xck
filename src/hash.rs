use crate::size::SIZE_32;

pub const BLAKE3_DEFAULT_CONTEXT: &str = "XCK VERSION 0.0.1 BLAKE3 DEFAULT CONTEXT";

pub fn blake3_digest(bytes: &[u8]) -> [u8; SIZE_32] {
    blake3::hash(bytes).into()
}

pub fn blake3_xof(bytes: &[u8], dst: &mut [u8]) {
    blake3::Hasher::new().update(bytes).finalize_xof().fill(dst);
}

pub fn blake3_kdf(context: &str, material: &[u8]) -> [u8; SIZE_32] {
    blake3::derive_key(context, material).into()
}

pub fn blake3_mac(key: [u8; SIZE_32], message: &[u8]) -> [u8; SIZE_32] {
    blake3::keyed_hash(&key, message).into()
}