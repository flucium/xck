use crate::{
    size::{SIZE_12, SIZE_24, SIZE_32},
    Error, ErrorKind, Result,
};
use aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

pub fn chacha20poly1305_encrypt(
    key: [u8; SIZE_32],
    nonce: [u8; SIZE_12],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    let aead = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
    aead_encrypt(aead, &nonce, aad, plain)
}

pub fn chacha20poly1305_decrypt(
    key: [u8; SIZE_32],
    nonce: [u8; SIZE_12],
    aad: &[u8],
    cipher: &[u8],
) -> Result<Vec<u8>> {
    let aead = ChaCha20Poly1305::new_from_slice(&key)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
    aead_decrypt(aead, &nonce, aad, cipher)
}

pub fn xchacha20poly1305_encrypt(
    key: [u8; SIZE_32],
    nonce: [u8; SIZE_24],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    let aead = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
    aead_encrypt(aead, &nonce, aad, plain)
}

pub fn xchacha20poly1305_decrypt(
    key: [u8; SIZE_32],
    nonce: [u8; SIZE_24],
    aad: &[u8],
    cipher: &[u8],
) -> Result<Vec<u8>> {
    let aead = XChaCha20Poly1305::new_from_slice(&key)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
    aead_decrypt(aead, &nonce, aad, cipher)
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
    let cipher = aead
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

// ______________________________
// /// Symmetric ...
// pub enum Symmetric<'a> {
//     ChaCha20Poly1305 {
//         key: Box<[u8; SIZE_32]>,
//         nonce: Box<[u8; SIZE_12]>,
//         aad: &'a [u8],
//         msg: &'a [u8],
//     },
//     XChaCha20Poly1305 {
//         key: Box<[u8; SIZE_32]>,
//         nonce: Box<[u8; SIZE_24]>,
//         aad: &'a [u8],
//         msg: &'a [u8],
//     },
// }

// impl Symmetric<'_> {
//     /// Encrypt ...
//     pub fn encrypt(self) -> Result<Vec<u8>> {
//         match self {
//             Self::ChaCha20Poly1305 {
//                 key,
//                 nonce,
//                 aad,
//                 msg,
//             } => aead_encrypt(
//                 ChaCha20Poly1305::new_from_slice(&*key)
//                     .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
//                 &*nonce,
//                 aad,
//                 msg,
//             ),
//             Self::XChaCha20Poly1305 {
//                 key,
//                 nonce,
//                 aad,
//                 msg,
//             } => aead_encrypt(
//                 XChaCha20Poly1305::new_from_slice(&*key)
//                     .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
//                 &*nonce,
//                 aad,
//                 msg,
//             ),
//         }
//     }

//     /// Decrypt ...
//     pub fn decrypt(self) -> Result<Vec<u8>> {
//         match self {
//             Self::ChaCha20Poly1305 {
//                 key,
//                 nonce,
//                 aad,
//                 msg,
//             } => aead_decrypt(
//                 ChaCha20Poly1305::new_from_slice(&*key)
//                     .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
//                 &*nonce,
//                 aad,
//                 msg,
//             ),
//             Self::XChaCha20Poly1305 {
//                 key,
//                 nonce,
//                 aad,
//                 msg,
//             } => aead_decrypt(
//                 XChaCha20Poly1305::new_from_slice(&*key)
//                     .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?,
//                 &*nonce,
//                 aad,
//                 msg,
//             ),
//         }
//     }
// }
