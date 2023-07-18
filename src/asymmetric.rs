use ed25519_dalek::{Signer, Verifier};

use crate::{
    rand::Rand,
    size::{SIZE_32, SIZE_64},
    Error, Result,
};

/// Ed25519 generate keypair.
pub fn ed25519_gen_keypair() -> ([u8; SIZE_32], [u8; SIZE_32]) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut Rand);

    let private_key = signing_key.to_bytes();

    let public_key = signing_key.verifying_key().to_bytes();

    (private_key, public_key)
}

/// Ed25519 Verifier.
pub fn ed25519_verify(
    public_key: &[u8; SIZE_32],
    message: &[u8],
    signature: &[u8; SIZE_64],
) -> Result<()> {
    ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|err| Error::new( err.to_string()))?
        .verify(message, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|err| Error::new( err.to_string()))
}

/// Ed25519 Signer.
pub fn ed25519_sign(private_key: &[u8; SIZE_32], message: &[u8]) -> Result<[u8; SIZE_64]> {
    let signature = ed25519_dalek::SigningKey::from_bytes(private_key)
        .try_sign(message)
        .map_err(|err| Error::new(err.to_string()))?;

    Ok(signature.to_bytes())
}