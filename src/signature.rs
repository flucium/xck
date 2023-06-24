use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};

use crate::{
    rand::Rand,
    size::{SIZE_32, SIZE_64},
    Error, ErrorKind, Result,
};

/// Ed25519 generate keypair ...
pub fn generate_keypair() -> ([u8; SIZE_32], [u8; SIZE_32]) {
    let keypair = Keypair::generate(&mut Rand);

    (keypair.secret.to_bytes(), keypair.public.to_bytes())
}

/// Ed25519 Sign ...
pub fn sign(
    private_key: &[u8; SIZE_32],
    public_key: &[u8; SIZE_32],
    message: &[u8],
) -> Result<[u8; SIZE_64]> {
    let bytes = Keypair {
        secret: SecretKey::from_bytes(private_key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
        public: PublicKey::from_bytes(public_key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
    }
    .sign(message);

    Ok(bytes.to_bytes())
}

/// Ed25519 Verify ...
pub fn verify(
    public_key: &[u8; SIZE_32],
    message: &[u8],
    signature: [u8; SIZE_64],
) -> Result<bool> {
    Ok(PublicKey::from_bytes(public_key)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?
        .verify(
            message,
            &Signature::from_bytes(&signature)
                .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
        )
        .is_ok())
}