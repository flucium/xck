use ed25519_dalek::{Signer, Verifier};

use crate::{
    rand::Rand,
    size::{SIZE_32, SIZE_64, SIZE_234, SIZE_51},
    Error, Result,
};

/// Ed25519 Generate Keypair.
///
/// The left of the returned value is the private_key and the right is the public_key. both are 32-byte, totaling 64 bytes.
///
/// # Example
/// ```
/// let (private_key,public_key) = xck::asymmetric::ed25519_gen_keypair();
///
/// println!("{:?}\n{:?}",private_key,public_key);
/// ```
pub fn ed25519_gen_keypair() -> ([u8; SIZE_32], [u8; SIZE_32]) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut Rand);

    let private_key = signing_key.to_bytes();

    let public_key = signing_key.verifying_key().to_bytes();

    (private_key, public_key)
}

/// Ed25519 Gemerate private-key.
pub fn ed25519_gen_private_key() -> [u8; SIZE_32] {
    ed25519_dalek::SigningKey::generate(&mut Rand).to_bytes()
}

/// Ed25519 Generate public-key from private-key.
pub fn ed25519_gen_public_key(private_key: &[u8; SIZE_32]) -> [u8; SIZE_32] {
    ed25519_dalek::VerifyingKey::from(&ed25519_dalek::SigningKey::from_bytes(private_key))
        .to_bytes()
}

/// Ed25519 Verifier.
///
/// Enter your public_key, message, and signature.
///
/// Result does not return an error if the authentication is successful. That is, `is_ok() == true`.
///
/// # Example
/// ```
/// let public_key:[u8;32] = [
///        8, 230, 98, 51, 57, 27, 17, 99, 190, 212, 187, 167, 138, 235, 172, 89, 144, 104, 152, 174,
///       242, 25, 168, 132, 53, 182, 187, 232, 142, 1, 1, 187,
///   ];
///
/// let signature:[u8;64] = [
///     83, 20, 131, 218, 63, 174, 163, 255, 37, 122, 54, 8, 232, 117, 239, 45, 201, 70, 101, 142,    
///     217, 147, 210, 94, 135, 222, 113, 244, 162, 251, 115, 56, 222, 63, 84, 150, 241, 44, 243,
///     138, 57, 64, 22, 0, 105, 198, 207, 240, 52, 170, 213, 157, 88, 49, 176, 187, 42, 12, 53,
///     79, 41, 22, 42, 3,
/// ]
///
/// let message:[u8; 5] = [104, 101, 108, 108, 111];
///
/// let is_ok = xck::asymmetric::ed25519_verify(&public_key,&message,&signature).is_ok();
///
/// println!("{}",is_ok);
/// ```
pub fn ed25519_verify(
    public_key: &[u8; SIZE_32],
    message: &[u8],
    signature: &[u8; SIZE_64],
) -> Result<()> {
    ed25519_dalek::VerifyingKey::from_bytes(public_key)
        .map_err(|err| Error::new(err.to_string()))?
        .verify(message, &ed25519_dalek::Signature::from_bytes(signature))
        .map_err(|err| Error::new(err.to_string()))
}

/// Ed25519 Signer.
///
/// Enter your private_key and message.
///
/// Signing with the correct keypair returns the signature. If it fails to sign with the wrong keypair, it returns an error message.
///
/// # Example
/// ```
/// let private_key:[u8; 32] = [
///     68, 87, 109, 156, 131, 213, 127, 10, 63, 10, 61, 181, 243, 100, 121, 102, 53, 62, 215, 212,
///     67, 223, 238, 9, 34, 39, 44, 10, 51, 2, 56, 96,
/// ];
///
/// let message:[u8; 5] = [104, 101, 108, 108, 111];
///
/// let signature = xck::asymmetric::ed25519_sign(&private_key, &message);
///
/// println!("{:?}",signature);
/// ```
pub fn ed25519_sign(private_key: &[u8; SIZE_32], message: &[u8]) -> Result<[u8; SIZE_64]> {
    let signature = ed25519_dalek::SigningKey::from_bytes(private_key)
        .try_sign(message)
        .map_err(|err| Error::new(err.to_string()))?;

    Ok(signature.to_bytes())
}

/// X25519 Generate Keypair
///
/// The left of the returned value is the private_key and the right is the public_key. both are 32-byte, totaling 64 bytes.
///
/// # Example
/// ```
/// let (private_key,public_key) = xck::asymmetric::x25519_gen_keypair();
///
/// println!("{:?}\n{:?}",private_key,public_key);
/// ```
pub fn x25519_gen_keypair() -> ([u8; SIZE_32], [u8; SIZE_32]) {
    let static_secret = x25519_dalek::StaticSecret::random_from_rng(&mut Rand);

    let public_key = x25519_dalek::PublicKey::from(&static_secret).to_bytes();

    let private_key = static_secret.to_bytes();

    (private_key, public_key)
}

/// X21159 Generate private-key.
pub fn x25519_gen_private_key() -> [u8; SIZE_32] {
    x25519_dalek::StaticSecret::random_from_rng(&mut Rand).to_bytes()
}

/// X25519 Generate public-key from private-key.
pub fn x25519_gen_public_key(private_key: &[u8; SIZE_32]) -> [u8; SIZE_32] {
    x25519_dalek::PublicKey::from(&x25519_dalek::StaticSecret::from(private_key.to_owned()))
        .to_bytes()
}

/// X25519 Diffie Hellman
///
/// You can obtain the same symmetric key with your private_key and the other their_public_key.
///
/// # Example
/// ```
/// let alice_private_key: [u8; 32] = [
///     45, 162, 45, 39, 64, 231, 153, 194, 122, 98, 107, 62, 92, 11, 143, 141, 125, 225, 86, 3,
///     112, 134, 89, 217, 7, 69, 94, 221, 58, 144, 165, 180,
/// ];
///
/// let alice_public_key: [u8; 32] = [
///     199, 120, 240, 236, 92, 200, 1, 149, 127, 9, 188, 222, 135, 251, 137, 2, 128, 66, 72, 94,
///     134, 137, 212, 88, 80, 229, 179, 223, 163, 149, 187, 10,
/// ];
///
/// let bob_private_key: [u8; 32] = [
///     19, 35, 157, 143, 14, 43, 61, 168, 28, 46, 239, 166, 39, 199, 173, 205, 230, 61, 131, 21,
///     101, 223, 149, 130, 156, 244, 213, 8, 164, 193, 89, 117,
/// ];
///
/// let bob_public_key: [u8; 32] = [
///     45, 63, 45, 131, 40, 198, 223, 245, 64, 24, 44, 61, 24, 246, 22, 106, 147, 11, 134, 240,
///     57, 15, 170, 207, 215, 72, 45, 177, 146, 142, 77, 55,
/// ];
///
/// let alice_shared: [u8; 32] = xck::asymmetric::x25519_diffie_hellman(&alice_private_key, &bob_public_key);
///
/// let bob_shared: [u8; 32] = xck::asymmetric::x25519_diffie_hellman(&bob_private_key, &alice_public_key);
///
/// println!("{}",alice_shared == bob_shared);
/// ```
pub fn x25519_diffie_hellman(
    private_key: &[u8; SIZE_32],
    their_public_key: &[u8; SIZE_32],
) -> [u8; SIZE_32] {
    let static_secret = x25519_dalek::StaticSecret::from(private_key.to_owned());

    let shared_secret =
        static_secret.diffie_hellman(&x25519_dalek::PublicKey::from(their_public_key.to_owned()));

    shared_secret.to_bytes()
}


pub fn ssh_ed25519_gen_private_key() -> Result<[u8; SIZE_234]> {
    let private_key: [u8; SIZE_234] =
        ssh_key::PrivateKey::random(&mut crate::rand::OsRng, ssh_key::Algorithm::Ed25519)
            .map_err(|err| Error::new(err.to_string()))?
            .to_bytes()
            .map_err(|err| Error::new(err.to_string()))?
            .as_slice()
            .try_into()
            .unwrap();

    Ok(private_key)
}

pub fn ssh_ed25519_gen_public_key(private_key: &[u8; SIZE_234]) -> Result<[u8; SIZE_51]> {
    let public_key: [u8; SIZE_51] = ssh_key::PrivateKey::from_bytes(private_key)
        .map_err(|err| Error::new(err.to_string()))?
        .public_key()
        .to_bytes()
        .map_err(|err| Error::new(err.to_string()))?
        .try_into()
        .unwrap();

    Ok(public_key)
}
