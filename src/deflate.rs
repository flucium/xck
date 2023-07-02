use crate::{Error, ErrorKind, Result};

use flate2::{
    write::{DeflateDecoder, DeflateEncoder, GzDecoder, GzEncoder, ZlibDecoder, ZlibEncoder},
    Compression,
};

use std::io::Write;

// Compression::default()
pub const DEFAULT_DEVEL: u32 = 6;

/// Gz Compress ...
pub fn gz_compress(level: u32, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = GzEncoder::new(Vec::new(), Compression::new(level));

    encoder
        .write_all(bytes)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    encoder
        .finish()
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))
}

/// Gz Decompress ...
pub fn gz_decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = GzDecoder::new(Vec::new());

    decoder
        .write_all(bytes)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    decoder
        .finish()
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))
}

/// Zlib Compress ...
pub fn zlib_compress(level: u32, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::new(level));

    encoder
        .write_all(bytes)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    encoder
        .finish()
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))
}

/// Zlib Decompress ...
pub fn zlib_decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = ZlibDecoder::new(Vec::new());

    decoder
        .write_all(bytes)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    decoder
        .finish()
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))
}

/// Deflate Compress ...
pub fn defalte_compress(level: u32, bytes: &[u8]) -> Result<Vec<u8>> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::new(level));

    encoder
        .write_all(bytes)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    encoder
        .finish()
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))
}

/// Deflate Decompress ...
pub fn deflate_decompress(bytes: &[u8]) -> Result<Vec<u8>> {
    let mut decoder = DeflateDecoder::new(Vec::new());

    decoder
        .write_all(bytes)
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;

    decoder
        .finish()
        .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))
}

// pub fn compress(level: u32, bytes: &[u8]) -> Result<Vec<u8>> {
//     defalte_compress(level, bytes)
// }

// pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>> {
//     deflate_decompress(bytes)
// }

// pub fn compress(bytes: &[u8]) -> Result<Vec<u8>> {
//     let mut encoder = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
//     encoder
//         .write(bytes)
//         .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
//     let bytes = encoder
//         .finish()
//         .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
//     Ok(bytes)
// }

// pub fn decompress(bytes: &[u8]) -> Result<Vec<u8>> {
//     let mut decoder = flate2::write::DeflateDecoder::new(Vec::new());
//     decoder
//         .write(bytes)
//         .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
//     let bytes = decoder
//         .finish()
//         .map_err(|err| Error::new(ErrorKind::Todo, err.to_string()))?;
//     Ok(bytes)
// }

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
