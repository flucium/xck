mod chacha;

use self::chacha::{ChaCha20Poly1305, XChaCha20Poly1305};

use crate::{
    size::{SIZE_U12, SIZE_U24, SIZE_U32},
    Error, ErrorKind, Result,
};

use aead::{Aead, KeyInit, Payload};

pub enum Symmetric<'a> {
    ChaCha20Poly1305 {
        key: Box<[u8; SIZE_U32]>,
        nonce: Box<[u8; SIZE_U12]>,
        aad: &'a [u8],
        msg: &'a [u8],
    },
    XChaCha20Poly1305 {
        key: Box<[u8; SIZE_U32]>,
        nonce: Box<[u8; SIZE_U24]>,
        aad: &'a [u8],
        msg: &'a [u8],
    },
}

impl Symmetric<'_> {
    pub fn encrypt(self) -> Result<Vec<u8>> {
        match self {
            Self::ChaCha20Poly1305 {
                key,
                nonce,
                aad,
                msg,
            } => aead_encrypt(
                ChaCha20Poly1305::new_from_slice(&*key)
                    .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
                &*nonce,
                aad,
                msg,
            ),
            Self::XChaCha20Poly1305 {
                key,
                nonce,
                aad,
                msg,
            } => aead_encrypt(
                XChaCha20Poly1305::new_from_slice(&*key)
                    .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
                &*nonce,
                aad,
                msg,
            ),
        }
    }

    pub fn decrypt(self) -> Result<Vec<u8>> {
        match self {
            Self::ChaCha20Poly1305 {
                key,
                nonce,
                aad,
                msg,
            } => aead_decrypt(
                ChaCha20Poly1305::new_from_slice(&*key)
                    .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
                &*nonce,
                aad,
                msg,
            ),
            Self::XChaCha20Poly1305 {
                key,
                nonce,
                aad,
                msg,
            } => aead_decrypt(
                XChaCha20Poly1305::new_from_slice(&*key)
                    .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
                &*nonce,
                aad,
                msg,
            ),
        }
    }
}

fn aead_decrypt(aead: impl Aead, nonce: &[u8], aad: &[u8], cipher: &[u8]) -> Result<Vec<u8>> {
    let plain = aead
        .decrypt(
            nonce.into(),
            Payload {
                msg: cipher,
                aad: aad,
            },
        )
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    Ok(plain)
}

fn aead_encrypt(aead: impl Aead, nonce: &[u8], aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let mut cipher = aead
        .encrypt(
            nonce.into(),
            Payload {
                msg: plain,
                aad: aad,
            },
        )
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    Ok(cipher)
}
