//! errors returned by our library and cli tools

#[derive(thiserror::Error, Debug, Clone)]
/// NNCP errors: parsing, key length and more
pub enum Error {
    #[error("Unable to parse {friendly_label} as base32")]
    Base32DecodeError {friendly_label: String},
    #[error("Incorrect key length for {friendly_label} - expected {expected_len}")]
    KeyLengthError{expected_len: usize, friendly_label: String},
}