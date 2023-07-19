use crate::{Error, Result};
use base64ct::{Base64, Encoding};

const BASE64_BUFFER_SIZE: usize = 1024;

/// Base64 Decode.
/// 
/// constant time.
/// 
/// # Example
/// ```
/// let b64_string = "aGVsbG8";
/// 
/// let bytes = xck::format::from_base64(&b64_string);
/// 
/// println!("{:?}",bytes);
/// ```
/// 
/// # Returns
/// ...
pub fn from_base64(b64_string: &str) -> Result<Vec<u8>> {
    let mut buf = [0u8; BASE64_BUFFER_SIZE];

    let bytes = Base64::decode(b64_string, &mut buf)
        .map_err(|err| Error::new( err.to_string()))?
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
/// let b64_string = xck::format::to_base64(bytes);
/// 
/// println!("{:?}",b64_string);
/// ```
/// 
/// # Returns
/// ...
pub fn to_base64(bytes: &[u8]) -> Result<String> {
    let mut buf = [0u8; BASE64_BUFFER_SIZE];

    let b64_string: String = Base64::encode(bytes, &mut buf)
        .map_err(|err| Error::new( err.to_string()))?
        .to_string();
    
    Ok(b64_string)
}

/// Hex Decode.
/// 
/// # Example
/// ```
/// let hex_string: &str = "68656c6c6f";
/// 
/// let bytes = xck::format::from_hex(hex_string);
/// 
/// println!("{:?}",bytes);
/// ```
/// 
/// # Returns
/// ...
pub fn from_hex(hex_string: &str) -> Vec<u8> {
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
/// let hex_string = xck::format::to_hex(bytes);
/// 
/// println!("{}",hex_string);
/// ```
/// 
/// # Returns
/// ...
pub fn to_hex(bytes: &[u8]) -> String {
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