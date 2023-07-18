pub mod rand;
mod size;
pub mod symmetric;
pub mod asymmetric;
pub mod hash;
pub mod format;

/// Result ...
pub type Result<T> = core::result::Result<T, Error>;

/// Error ...
#[derive(Debug)]
pub struct Error {
    kind: ErrorKind,
    message: String,
}

impl Error {
    pub fn new(kind: ErrorKind, message: String) -> Self {
        Self {
            kind: kind,
            message: message,
        }
    }

    pub fn kind(&self) -> &ErrorKind {
        &self.kind
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}

/// ErrorKind ...
#[derive(Debug)]
pub enum ErrorKind {
    Uncategorized,
    SignatureError,
    IOError,
    EncodingFailed,
    DecodingFailed,
    EncryptionFailed,
    DecryptionFailed,
}
