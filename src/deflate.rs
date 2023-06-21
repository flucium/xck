use std::io::{self, Write};

use flate2::{
    /*read::{DeflateDecoder, DeflateEncoder},*/
    Compression,
};

/// Deflate compress
pub fn compress(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut deflate = flate2::write::DeflateEncoder::new(Vec::new(), Compression::default());
    deflate.write_all(bytes)?;

    let finish = deflate.finish()?;
    Ok(finish)
}

/// Deflate decompress
pub fn decompress(bytes: &[u8]) -> io::Result<Vec<u8>> {
    let mut deflate = flate2::write::DeflateDecoder::new(Vec::new());
    deflate.write_all(bytes)?;

    let finish = deflate.finish()?;
    Ok(finish)
}
