use crate::{size::SIZE_32, Error, Result};
use base64ct::{Base64, Encoding};
use pem_rfc7468::LineEnding;

type Label<'a> = &'a str;

const BASE64_BUFFER_SIZE: usize = 1024;

#[cfg(target_os = "macos")]
const LINE_ENDING: LineEnding = pem_rfc7468::LineEnding::CR;

#[cfg(target_os = "linux")]
const LINE_ENDING: LineEnding = pem_rfc7468::LineEnding::LF;

#[cfg(target_os = "windows")]
const LINE_ENDING: LineEnding = pem_rfc7468::LineEnding::CRLF;


pub const PEM_LABEL_PRIVATE_KEY: Label = "PRIVATE KEY";

pub const PEM_LABEL_PUBLIC_KEY: Label = "PUBLIC KEY";



/// Base64 Decode.
///
/// constant time.
///
/// # Example
/// ```
/// let b64_string = "aGVsbG8";
///
/// let bytes = xck::format::base64_decode(&b64_string);
///
/// println!("{:?}",bytes);
/// ```
pub fn base64_decode(b64_string: &str) -> Result<Vec<u8>> {
    let mut buf = [0u8; BASE64_BUFFER_SIZE];

    let bytes = Base64::decode(b64_string, &mut buf)
        .map_err(|err| Error::new(err.to_string()))?
        .to_vec();

    Ok(bytes)
}

/// Base64 Encode.
///
/// constant time.
///
/// # Example
/// ```
/// let bytes: [u8; 5] = [104, 101, 108, 108, 111];
///
/// let b64_string = xck::format::base64_encode(bytes);
///
/// println!("{:?}",b64_string);
/// ```
pub fn base64_encode(bytes: &[u8]) -> Result<String> {
    let mut buf = [0u8; BASE64_BUFFER_SIZE];

    let b64_string: String = Base64::encode(bytes, &mut buf)
        .map_err(|err| Error::new(err.to_string()))?
        .to_string();

    Ok(b64_string)
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
pub fn hex_decode(hex_string: &str) -> Vec<u8> {
    let bytes = hex_string.as_bytes();

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
pub fn hex_encode(bytes: &[u8]) -> String {
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


/// PEM Encode
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
pub fn pem_encode<'a>(label: Label<'a>, key: &[u8; SIZE_32]) -> Result<String> {
    let mut buf: [u8; 1024] = [0u8; 1024];

    let string = pem_rfc7468::encode(label, LINE_ENDING, key, &mut buf)
        .map_err(|err| Error::new(err.to_string()))?;

    Ok(string.to_owned())
}

/// PEM Decode
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
    let mut buf: [u8; 1024] = [0u8; 1024];

    let (label, bytes) =
        pem_rfc7468::decode(pem, &mut buf).map_err(|err| Error::new(err.to_string()))?;

    if bytes.len() != SIZE_32 {
        Err(Error::new("".to_owned()))?
    }

    Ok((label, bytes.try_into().unwrap()))
}