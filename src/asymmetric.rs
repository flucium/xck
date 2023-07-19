use ed25519_dalek::{Signer, Verifier};

use crate::{
    rand::Rand,
    size::{SIZE_32, SIZE_64},
    Error, Result,
};

/// Ed25519 generate keypair.
/// 
/// # Example
/// ```
/// let (private_key,public_key) = xck::asymmetric::ed25519_gen_keypair();
/// 
/// println!("{:?}\n{:?}",private_key,public_key);
/// ```
/// 
/// # Returns
/// ...
pub fn ed25519_gen_keypair() -> ([u8; SIZE_32], [u8; SIZE_32]) {
    let signing_key = ed25519_dalek::SigningKey::generate(&mut Rand);

    let private_key = signing_key.to_bytes();

    let public_key = signing_key.verifying_key().to_bytes();

    (private_key, public_key)
}

/// Ed25519 Verifier.
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
/// 
/// # Returns
/// ....
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
///
/// # Returns
/// ....
pub fn ed25519_sign(private_key: &[u8; SIZE_32], message: &[u8]) -> Result<[u8; SIZE_64]> {
    let signature = ed25519_dalek::SigningKey::from_bytes(private_key)
        .try_sign(message)
        .map_err(|err| Error::new(err.to_string()))?;

    Ok(signature.to_bytes())
}