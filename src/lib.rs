pub mod asymmetric;
pub mod format;
pub mod hash;
pub mod rand;
mod size;
pub mod symmetric;

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
// pub struct Error {
//     message: String,
// }
pub struct Error(String);

impl Error {
    fn new(message: String) -> Self {
        Self(message)
    }

    pub fn message(&self) -> &str {
        &self.0
    }
}
