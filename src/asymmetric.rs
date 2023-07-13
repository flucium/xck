use crate::{
    size::{SIZE_32, SIZE_64},
    Error, ErrorKind, Result,
};

use ed25519_dalek::{Signer, Verifier};

pub fn x25519_diffiehellman(
    private_key: &[u8; SIZE_32],
    their_public: &[u8; SIZE_32],
) -> [u8; SIZE_32] {
    x25519_dalek::StaticSecret::from(*private_key)
        .diffie_hellman(&x25519_dalek::PublicKey::from(*their_public))
        .to_bytes()
}

pub fn x25519_gen_keypair() -> ([u8; SIZE_32], [u8; SIZE_32]) {
    let static_secret = x25519_dalek::StaticSecret::random_from_rng(&mut rand::rngs::OsRng);

    let public_key = x25519_dalek::PublicKey::from(&static_secret);

    (static_secret.to_bytes(), public_key.to_bytes())
}

pub fn ed25519_verify(
    public_key: &[u8; SIZE_32],
    signature: &[u8; SIZE_64],
    msg: &[u8],
) -> Result<bool> {
    let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    let signature = ed25519_dalek::Signature::from_bytes(signature);

    let is_ok = verifying_key.verify(msg, &signature).is_ok();

    Ok(is_ok)
}

pub fn ed25519_sign(private_key: &[u8; SIZE_32], msg: &[u8]) -> Result<[u8; SIZE_64]> {
    let signing_key = ed25519_dalek::SigningKey::from_bytes(private_key);

    let signature = signing_key
        .try_sign(msg)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    let signature_bytes = signature.to_bytes();

    Ok(signature_bytes)
}

pub fn ed25519_gen_keypair() -> ([u8; SIZE_32], [u8; SIZE_32]) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);

    let verifying_key = signing_key.verifying_key();

    (signing_key.to_bytes(), verifying_key.to_bytes())
}
