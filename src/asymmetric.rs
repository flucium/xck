use ed25519_dalek::{ed25519::signature::SignerMut, Verifier};

use crate::{
    rand::Rand,
    size::{SIZE_32, SIZE_64},
    Error, ErrorKind, Result,
};

pub fn ed25519_sign(
    private_key: [u8; SIZE_32],
    public_key: [u8; SIZE_32],
    message: &[u8],
) -> Result<[u8; SIZE_64]> {
    let secretkey = ed25519_dalek::SecretKey::from_bytes(&private_key)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    let publickey = ed25519_dalek::PublicKey::from_bytes(&public_key)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    let signature = ed25519_dalek::Keypair {
        secret: secretkey,
        public: publickey,
    }
    .sign(message)
    .to_bytes();

    Ok(signature)
}

pub fn ed25519_verify(
    public_key: [u8; SIZE_32],
    message: &[u8],
    signature: [u8; SIZE_64],
) -> Result<bool> {
    let is_ok = ed25519_dalek::PublicKey::from_bytes(&public_key)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?
        .verify(
            message,
            &ed25519_dalek::Signature::from_bytes(&signature)
                .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
        )
        .is_ok();
    Ok(is_ok)
}

pub fn ed25519_gen_keypair() -> ([u8; SIZE_32], [u8; SIZE_32]) {
    let keypair = ed25519_dalek::Keypair::generate(&mut Rand);
    (keypair.secret.to_bytes(), keypair.public.to_bytes())
}

// pub fn x25519_(){ }

// pub fn x25519_gen_keypair(){}
