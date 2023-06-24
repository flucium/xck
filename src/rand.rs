use crate::size::*;

use rand::{Rng, SeedableRng};

use rand_chacha::ChaCha20Rng;

use rand_core::{CryptoRng, Error, RngCore};


/// A cryptography rand generator. ChaCha20Rng.
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
//
/// Generates a 32-byte cryptographic pseudo random number.
pub fn generate() -> [u8; SIZE_32] {
    let mut rng = ChaCha20Rng::from_entropy();

    let bytes = rng.gen::<[u8; SIZE_32]>();

    bytes
}