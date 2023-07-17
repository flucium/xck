use crate::size::*;

use rand::{Rng, SeedableRng};

#[cfg(not(feature = "lower"))]
use rand_chacha::{
    rand_core::{CryptoRng, Error, RngCore},
    ChaCha20Rng as ChaChaRng,
};

#[cfg(feature = "lower")]
use rand_chacha::{
    rand_core::{CryptoRng, Error, RngCore},
    ChaCha8Rng as ChaChaRng,
};

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

pub fn generate() -> [u8; SIZE_32] {
    gen_32()
}

pub fn gen_32() -> [u8; SIZE_32] {
    ChaChaRng::from_entropy().gen::<[u8; SIZE_32]>()
}

pub fn gen_24() -> [u8; SIZE_24] {
    ChaChaRng::from_entropy().gen::<[u8; SIZE_24]>()
}

pub fn gen_16() -> [u8; SIZE_16] {
    ChaChaRng::from_entropy().gen::<[u8; SIZE_16]>()
}

pub fn gen_12() -> [u8; SIZE_12] {
    ChaChaRng::from_entropy().gen::<[u8; SIZE_12]>()
}