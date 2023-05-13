//! errors returned by our library and cli tools

#[derive(thiserror::Error, Debug, Clone)]
/// NNCP errors: parsing, key length and more
pub enum NNCPError {
    #[error("Unable to parse as base32")]
    Base32DecodeError ,
    #[error("Incorrect key length - expected {expected_len}")]
    KeyLengthError{expected_len: usize},
}