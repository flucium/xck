
// pub fn decrypt() {}

// pub fn encrypt() {}

pub mod raw {
    use crate::{
        size::{SIZE_12, SIZE_16, SIZE_24, SIZE_32},
        Error, ErrorKind, Result,
    };

    use aead::{Aead, KeyInit, Payload};

    use aes_gcm::{Aes128Gcm, Aes256Gcm};

    use chacha20poly1305::{ChaCha20Poly1305, XChaCha20Poly1305};

    type Aes192Gcm = aes_gcm::AesGcm<aes_gcm::aes::Aes192, aes_gcm::aead::consts::U12>;

    pub fn aes_256_gcm_decrypt(
        key: &[u8; SIZE_32],
        nonce: &[u8; SIZE_12],
        aad: &[u8],
        cipher: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = Aes256Gcm::new_from_slice(key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

        aead_decrypt(aead, nonce, aad, cipher)
    }

    pub fn aes_256_gcm_encrypt(
        key: &[u8; SIZE_32],
        nonce: &[u8; SIZE_12],
        aad: &[u8],
        plain: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = Aes256Gcm::new_from_slice(key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
        aead_encrypt(aead, nonce, aad, plain)
    }

    pub fn aes_192_gcm_decrypt(
        key: &[u8; SIZE_24],
        nonce: &[u8; SIZE_12],
        aad: &[u8],
        cipher: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = Aes192Gcm::new_from_slice(key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
        aead_decrypt(aead, nonce, aad, cipher)
    }

    pub fn aes_192_gcm_encrypt(
        key: &[u8; SIZE_24],
        nonce: &[u8; SIZE_12],
        aad: &[u8],
        plain: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = Aes192Gcm::new_from_slice(key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
        aead_encrypt(aead, nonce, aad, plain)
    }

    pub fn aes_128_gcm_decrypt(
        key: &[u8; SIZE_16],
        nonce: &[u8; SIZE_12],
        aad: &[u8],
        cipher: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = Aes128Gcm::new_from_slice(key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
        aead_decrypt(aead, nonce, aad, cipher)
    }

    pub fn aes_128_gcm_encrypt(
        key: &[u8; SIZE_16],
        nonce: &[u8; SIZE_12],
        aad: &[u8],
        plain: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = Aes128Gcm::new_from_slice(key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
        aead_encrypt(aead, nonce, aad, plain)
    }

    pub fn xchacha20poly1305_decrypt(
        key: &[u8; SIZE_32],
        nonce: &[u8; SIZE_24],
        aad: &[u8],
        cipher: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
        aead_decrypt(aead, nonce, aad, cipher)
    }

    pub fn xchacha20poly1305_encrypt(
        key: &[u8; SIZE_32],
        nonce: &[u8; SIZE_24],
        aad: &[u8],
        plain: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = XChaCha20Poly1305::new_from_slice(key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
        aead_encrypt(aead, nonce, aad, plain)
    }

    pub fn chacha20poly1305_decrypt(
        key: &[u8; SIZE_32],
        nonce: &[u8; SIZE_12],
        aad: &[u8],
        cipher: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
        aead_decrypt(aead, nonce, aad, cipher)
    }

    pub fn chacha20poly1305_encrypt(
        key: &[u8; SIZE_32],
        nonce: &[u8; SIZE_12],
        aad: &[u8],
        plain: &[u8],
    ) -> Result<Vec<u8>> {
        let aead = ChaCha20Poly1305::new_from_slice(key)
            .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
        aead_encrypt(aead, nonce, aad, plain)
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
}
