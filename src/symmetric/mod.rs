mod chacha;

use crate::{rand::generate, Error, ErrorKind, Result};

use aead::{Aead, Payload};

fn aead_decrypt(aead: impl Aead, nonce_size: usize, aad: &[u8], cipher: &[u8]) -> Result<Vec<u8>> {
    let len = cipher.len() - nonce_size;

    let nonce = match cipher.get(len..) {
        None => return Err(Error::new(ErrorKind::Todo, "".to_string())),
        Some(nonce) => nonce,
    };

    let cipher = match cipher.get(..len) {
        None => return Err(Error::new(ErrorKind::Todo, "".to_string())),
        Some(cipher) => cipher,
    };

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

fn aead_encrypt(aead: impl Aead, nonce_size: usize, aad: &[u8], plain: &[u8]) -> Result<Vec<u8>> {
    let r = generate();
    let nonce = r.get(0..nonce_size).unwrap();

    let mut cipher = aead
        .encrypt(
            nonce.into(),
            Payload {
                msg: plain,
                aad: aad,
            },
        )
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    cipher.append(&mut nonce.to_vec());

    Ok(cipher)
}
