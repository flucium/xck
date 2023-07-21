use crate::size::*;

use rand::{Rng, SeedableRng};

use rand_chacha::{
    rand_core::{CryptoRng, Error, RngCore},
    ChaCha20Rng,
};

/// Rand implements RngCore and CryptoRng.
///
/// Internally, ChaCha20Rng.
#[derive(Clone, Copy, Debug, Default)]
pub struct Rand;

impl CryptoRng for Rand {}

impl RngCore for Rand {
    fn next_u32(&mut self) -> u32 {
        let mut buf: [u8; 4] = [0; 4];

        self.fill_bytes(&mut buf);

        u32::from_le_bytes(buf)
    }

    fn next_u64(&mut self) -> u64 {
        let mut buf: [u8; 8] = [0; 8];

        self.fill_bytes(&mut buf);

        u64::from_be_bytes(buf)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        self.try_fill_bytes(dest).unwrap();
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        dest.copy_from_slice(&generate());
        Ok(())
    }
}

/// ChaCha20Rng
///
/// Generates a 32-byte random bytes.
///
/// # Example
/// ```
/// let bytes = xck::rand::generate();
///
/// println!("{:?}",bytes);
/// ```
///
/// # Returns
/// ...
pub fn generate() -> [u8; SIZE_32] {
    gen_32()
}

/// ChaCha20Rng
///
/// Generates a 32-byte random bytes.
///
/// # Example
/// ```
/// let bytes = xck::rand::gen_32();
///
/// println!("{:?}",bytes);
/// ```
///
/// # Returns
/// ...
pub fn gen_32() -> [u8; SIZE_32] {
    ChaCha20Rng::from_entropy().gen::<[u8; SIZE_32]>()
}

/// ChaCha20Rng
///
/// Generates a 24-byte random bytes.
///
/// # Example
/// ```
/// let bytes = xck::rand::gen_24();
///
/// println!("{:?}",bytes);
/// ```
///
/// # Returns
/// ...
pub fn gen_24() -> [u8; SIZE_24] {
    ChaCha20Rng::from_entropy().gen::<[u8; SIZE_24]>()
}

/// ChaCha20Rng
///
/// Generates a 16-byte random bytes.
///
/// # Example
/// ```
/// let bytes = xck::rand::gen_16();
///
/// println!("{:?}",bytes);
/// ```
///
/// # Returns
/// ...
pub fn gen_16() -> [u8; SIZE_16] {
    ChaCha20Rng::from_entropy().gen::<[u8; SIZE_16]>()
}

/// ChaCha20Rng
///
/// Generates a 12-byte random bytes.
///
/// # Example
/// ```
/// let bytes = xck::rand::gen_12();
///
/// println!("{:?}",bytes);
/// ```
///
/// # Returns
/// ...
pub fn gen_12() -> [u8; SIZE_12] {
    ChaCha20Rng::from_entropy().gen::<[u8; SIZE_12]>()
}
