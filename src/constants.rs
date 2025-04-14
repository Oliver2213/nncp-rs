//! Constants used throughout the NNCP crate

/// Maximum size of a path in a packet
pub const MAX_PATH_SIZE: usize = 255;

/// Size of a Merkle Tree Hash
pub const MTH_SIZE: usize = 32;

/// Base32 encoded length of a 32-byte value
pub const BASE32_ENCODED_32_LEN: usize = 52;

/// Encryption block size (128 KB)
pub const ENC_BLK_SIZE: usize = 128 * 1024;

/// NNCP bundle prefix
pub const NNCP_BUNDLE_PREFIX: &str = "NNCP";

/// The noise pattern used by nncp
pub static NOISE_PROTO_PATTERN: &str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

/// Our long about text, describing briefly what nncp is and what this program is and is not.
pub static LONG_ABOUT: &str = r###"
NNCP (Node to Node copy) is a collection of utilities simplifying secure store-and-forward file, mail and command exchange.
Currently aiming for on-disk compatibility, then on-wire.
See nncpgo.org for info; I am not the original author.
"###;
