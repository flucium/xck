pub mod asymmetric;
pub mod format;
pub mod hash;
pub mod rand;
mod size;
pub mod symmetric;

/// Result ...
pub type Result<T> = core::result::Result<T, Error>;

/// Error ...
#[derive(Debug)]
pub struct Error {
    message: String,
}

impl Error {
    pub fn new(message: String) -> Self {
        Self {
            message: message,
        }
    }

    pub fn message(&self) -> &str {
        &self.message
    }
}