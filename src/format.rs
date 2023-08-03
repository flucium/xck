#[cfg(feature = "alloc")]
extern crate alloc;

#[cfg(feature = "alloc")]
use alloc::{string::String, vec::Vec};

use crate::{size::SIZE_32, Error, Result};
use base64ct::{Base64, Encoding};

type Label<'a> = &'a str;

const BASE64_BUFFER_SIZE: usize = 256;

const PEM_BUFFER_SIZE: usize = 1024;

#[cfg(target_os = "macos")]
const LINE_ENDING: pem_rfc7468::LineEnding = pem_rfc7468::LineEnding::LF;

#[cfg(target_os = "linux")]
const LINE_ENDING: pem_rfc7468::LineEnding = pem_rfc7468::LineEnding::LF;

#[cfg(target_os = "windows")]
const LINE_ENDING: pem_rfc7468::LineEnding = pem_rfc7468::LineEnding::CRLF;

pub const PEM_LABEL_PRIVATE_KEY: Label = "PRIVATE KEY";

pub const PEM_LABEL_PUBLIC_KEY: Label = "PUBLIC KEY";

/// Base64 Decode.
///
/// constant time. max size: 256-byte.
///
/// # Example
/// ```
/// let b64_string = "aGVsbG8";
///
/// let (bytes, len) = xck::format::base64_decode(&b64_string).unwrap();
///
/// println!("{:?}",bytes[..len]);
/// ```
pub fn base64_decode(b64_string: impl Into<String>) -> Result<([u8; BASE64_BUFFER_SIZE], usize)> {
    let mut buf = [0u8; BASE64_BUFFER_SIZE];

    let len = Base64::decode(b64_string.into(), &mut buf)
        .map_err(|err| Error::new(err.to_string()))?
        .len();

    Ok((buf, len))
}

/// Base64 Encode.
///
/// constant time. max size: 256-byte.
///
/// # Example
/// ```
/// let bytes: [u8; 5] = [104, 101, 108, 108, 111];
///
/// let (encoded,len) = xck::format::base64_encode(bytes);
///
/// println!("{:?}",String::from_utf8_lossy(&encoded[0..len]));
/// ```
pub fn base64_encode(bytes: &[u8]) -> Result<([u8; BASE64_BUFFER_SIZE], usize)> {
    let mut buf = [0u8; BASE64_BUFFER_SIZE];

    let len = Base64::encode(bytes, &mut buf)
        .map_err(|err| Error::new(err.to_string()))?
        .len();

    Ok((buf, len))
}

/// Base64 Decode
#[cfg(feature = "alloc")]
pub fn base64_decode_alloc(b64_string: impl Into<String>) -> Result<Vec<u8>> {
    let bytes =
        Base64::decode_vec(&b64_string.into()).map_err(|err| Error::new(err.to_string()))?;

    Ok(bytes)
}

/// Base64 Encode
#[cfg(feature = "alloc")]
pub fn base64_encode_alloc(bytes: &[u8]) -> String {
    Base64::encode_string(bytes)
}

/// Hex Decode.
///
/// # Example
/// ```
/// let hex_string: &str = "68656c6c6f";
///
/// let bytes = xck::format::hex_decode(hex_string);
///
/// println!("{:?}",bytes);
/// ```
#[cfg(feature = "alloc")]
pub fn hex_decode_alloc(hex_string: impl Into<String>) -> Vec<u8> {
    let string = hex_string.into();

    let bytes = string.as_bytes();

    let len = bytes.len() / 2;

    let mut buf = Vec::with_capacity(len);

    for i in 0..len {
        let index = i * 2;

        let s = (bytes[index] << 4) as u32;

        let b = (bytes[index + 1] as char).to_digit(16).unwrap();

        let byte = (s + b) as u8;

        buf.push(byte);
    }

    buf
}

/// Hex Encode.
///
/// # Example
/// ```
/// let bytes: [u8; 5] = [104, 101, 108, 108, 111];
///
/// let hex_string = xck::format::hex_encode(bytes);
///
/// println!("{}",hex_string);
/// ```
#[cfg(feature = "alloc")]
pub fn hex_encode_alloc(bytes: &[u8]) -> String {
    //'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
    const HEX_TABLE: [u8; 16] = [
        48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 97, 98, 99, 100, 101, 102,
    ];

    let mut buf = Vec::with_capacity(bytes.len() * 2);

    for byte in bytes {
        let s_index = (byte >> 4) as usize;
        buf.push(HEX_TABLE[s_index]);

        let b_index = (byte & 0xF) as usize;
        buf.push(HEX_TABLE[b_index]);
    }

    String::from_utf8(buf).unwrap()
}

/// PEM Encode (pem rfc7468)
///
/// Only 32-byte keypair are supported. Specifically X25519 and Ed25519.
///
/// # Example
/// ```
/// let (private_key,public_key) = xck::asymmetric::ed25519_gen_keypair();
///
/// let private_key_pem = xck::format::pem_encode(PEM_LABEL_PRIVATE_KEY,&private_key).unwrap();
///
/// let private_key_pem = xck::format::pem_encode(PEM_LABEL_PUBLIC_KEY,&private_key).unwrap();
///
/// println!("{private_key_pem}\n{public_key_pem}");
/// ```
pub fn pem_encode(label: Label, key: &[u8; SIZE_32]) -> Result<String> {
    let mut buf: [u8; 1024] = [0u8; PEM_BUFFER_SIZE];

    let string = pem_rfc7468::encode(label, LINE_ENDING, key, &mut buf)
        .map_err(|err| Error::new(err.to_string()))?;

    Ok(string.to_string())
}

/// PEM Decode (pem rfc7468)
///
/// Only 32-byte keypair are supported. Specifically X25519 and Ed25519.
///
/// # Example
/// ```
/// let pem = "-----BEGIN PRIVATE KEY-----\rZ35L3PuHG0Vkkowk5Fzj6VA5jCus5LKedwT2IPe2+Rc=\r-----END PRIVATE KEY-----\r";
///
/// let decoded = xck::format::pem_decode(pem.as_bytes()).unwrap();
///
/// let label = decoded.0;
///
/// let key = decoded.1;
///
/// println!("Label: {}\nKey: {:?}",label,key);
/// ```
pub fn pem_decode(pem: &[u8]) -> Result<(Label, [u8; SIZE_32])> {
    let mut buf: [u8; 1024] = [0u8; PEM_BUFFER_SIZE];

    let (label, bytes) =
        pem_rfc7468::decode(pem, &mut buf).map_err(|err| Error::new(err.to_string()))?;
    
    if bytes.len() != SIZE_32 {
        Err(Error::new("".to_owned()))?
    }

    Ok((label, bytes.try_into().unwrap()))
}
