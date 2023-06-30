use crate::{Error, ErrorKind, Result};
use flate2::Compression;
use std::io::Write;

pub fn compress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
    encoder
        .write(bytes)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
    let bytes = encoder
        .finish()
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
    Ok(bytes)
}

pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = flate2::write::DeflateDecoder::new(Vec::new());
    decoder
        .write(bytes)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
    let bytes = decoder
        .finish()
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
    Ok(bytes)
}

// Deflate compress from io::Read
// pub fn compress_from_read<R>(r: R) -> Result<Vec<u8>>
// where
//     R: Read,
// {
//     let mut buf = Vec::new();
//     flate2::read::DeflateEncoder::new(r, Compression::default())
//         .read_to_end(&mut buf)
//         .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
//     Ok(buf)
// }

// Deflate decompress from io::Read
// pub fn decompress_from_read<R>(r: R) -> Result<Vec<u8>>
// where
//     R: Read,
// {
//     let mut buf = Vec::new();
//     flate2::read::DeflateDecoder::new(r)
//         .read_to_end(&mut buf)
//         .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
//     Ok(buf)
// }
