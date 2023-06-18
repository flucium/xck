use crate::size::{SIZE_U32, SIZE_U64};
use digest::Digest;
use sha2::{Sha256, Sha512, Sha512_256};

/// SHA2
pub fn sha256(bytes: &[u8]) -> [u8; SIZE_U32] {
    Sha256::digest(bytes).into()
}

/// SHA2 521
pub fn sha512(bytes: &[u8]) -> [u8; SIZE_U64] {
    Sha512::digest(bytes).into()
}

/// SHA2 512/256
pub fn sha512_256(bytes: &[u8]) -> [u8; SIZE_U32] {
    Sha512_256::digest(bytes).into()
}
