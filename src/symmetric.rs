use aead::{Aead, KeyInit, Payload};

use crate::{
    size::{SIZE_12, SIZE_16, SIZE_24, SIZE_32},
    Error, Result,
};

use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

use aes_gcm::{Aes128Gcm, Aes256Gcm};

type Aes192Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes192, aead::consts::U12>;

/// AES 256 GCM Decrypt
///
/// The Key is 32-byte and the Nonce is 12-byte.
///
/// If you want Aad to be empty, use &[].
///
/// Message is cipher bytes.
pub fn aes_256_gcm_decrypt(
    key: &[u8; SIZE_32],
    nonce: &[u8; SIZE_12],
    aad: &[u8],
    cipher: &[u8],
) -> Result<Vec<u8>> {
    aead_decrypt(Aes256Gcm::new_from_slice(key).unwrap(), nonce, aad, cipher)
}

/// AES 256 Encrypt
///
/// The Key is 32-byte and the Nonce is 12-byte.
///
/// If you want Aad to be empty, use &[].
///
/// Message is plain bytes.
pub fn aes_256_gcm_encrypt(
    key: &[u8; SIZE_32],
    nonce: &[u8; SIZE_12],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    aead_encrypt(Aes256Gcm::new_from_slice(key).unwrap(), nonce, aad, plain)
}

/// AES 192 Decrypt
///
/// The Key is 24-byte and the Nonce is 12-byte.
///
/// If you want Aad to be empty, use &[].
///
/// Message is cipher bytes.
pub fn aes_192_gcm_decrypt(
    key: &[u8; SIZE_24],
    nonce: &[u8; SIZE_12],
    aad: &[u8],
    cipher: &[u8],
) -> Result<Vec<u8>> {
    aead_decrypt(Aes192Gcm::new_from_slice(key).unwrap(), nonce, aad, cipher)
}

/// AES 192 Encrypt
///
/// The Key is 24-byte and the Nonce is 12-byte.
///
/// If you want Aad to be empty, use &[].
///
/// Message is plain bytes.
pub fn aes_192_gcm_encrypt(
    key: &[u8; SIZE_24],
    nonce: &[u8; SIZE_12],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    aead_encrypt(Aes192Gcm::new_from_slice(key).unwrap(), nonce, aad, plain)
}

/// AES 128 Decrypt
///
/// The Key is 16-byte and the Nonce is 12-byte.
///
/// If you want Aad to be empty, use &[].
///
/// Message is cipher bytes.
pub fn aes_128_gcm_decrypt(
    key: &[u8; SIZE_16],
    nonce: &[u8; SIZE_12],
    aad: &[u8],
    cipher: &[u8],
) -> Result<Vec<u8>> {
    aead_decrypt(Aes128Gcm::new_from_slice(key).unwrap(), nonce, aad, cipher)
}

/// AES 128 Encrypt
///
/// The Key is 16-byte and the Nonce is 12-byte.
///
/// If you want Aad to be empty, use &[].
///
/// Message is plain bytes.
pub fn aes_128_gcm_encrypt(
    key: &[u8; SIZE_16],
    nonce: &[u8; SIZE_12],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    aead_encrypt(Aes128Gcm::new_from_slice(key).unwrap(), nonce, aad, plain)
}

/// XChaCha20 Poly1305 Decrypt
///
/// The Key is 32-byte and the Nonce is 24-byte.
///
/// If you want Aad to be empty, use &[].
///
/// Message is cipher bytes.
pub fn xchacha20_poly1305_decrypt(
    key: &[u8; SIZE_32],
    nonce: &[u8; SIZE_24],
    aad: &[u8],
    cipher: &[u8],
) -> Result<Vec<u8>> {
    aead_decrypt(
        XChaCha20Poly1305::new_from_slice(key).unwrap(),
        nonce,
        aad,
        cipher,
    )
}

/// XChaCha20 Poly1305 Encrypt
///
/// The Key is 32-byte and the Nonce is 24-byte.
///
/// If you want Aad to be empty, use &[].
///
/// Message is plain bytes.
pub fn xchacha20_poly1305_encrypt(
    key: &[u8; SIZE_32],
    nonce: &[u8; SIZE_24],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    aead_encrypt(
        XChaCha20Poly1305::new_from_slice(key).unwrap(),
        nonce,
        aad,
        plain,
    )
}

/// ChaCha20 Poly1305 Decrypt
///
/// The Key is 32-byte and the Nonce is 12-byte.
///
/// If you want Aad to be empty, use &[].
///
/// Message is cipher bytes.
pub fn chacha20_poly1305_decrypt(
    key: &[u8; SIZE_32],
    nonce: &[u8; SIZE_12],
    aad: &[u8],
    cipher: &[u8],
) -> Result<Vec<u8>> {
    aead_decrypt(
        ChaCha20Poly1305::new_from_slice(key).unwrap(),
        nonce,
        aad,
        cipher,
    )
}

/// ChaCha20 Poly1305 Encrypt
///
/// The Key is 32-byte and the Nonce is 12-byte.
///
/// If you want Aad to be empty, use &[].
///
/// Message is plain bytes.
pub fn chacha20_poly1305_encrypt(
    key: &[u8; SIZE_32],
    nonce: &[u8; SIZE_12],
    aad: &[u8],
    plain: &[u8],
) -> Result<Vec<u8>> {
    aead_encrypt(
        ChaCha20Poly1305::new_from_slice(key).unwrap(),
        nonce,
        aad,
        plain,
    )
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
        .map_err(|err| Error::new(err.to_string()))?;

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
        .map_err(|err| Error::new(err.to_string()))?;

    Ok(cipher)
}
