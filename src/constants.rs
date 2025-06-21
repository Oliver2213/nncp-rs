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

/// Magic number for NNCP encrypted packet version 6
pub const NNCP_E_V6_MAGIC: [u8; 8] = [b'N', b'N', b'C', b'P', b'E', 0, 0, 6];

/// Poly1305 authentication tag size
pub const POLY1305_TAG_SIZE: usize = 16;

/// Key derivation contexts for encrypted packets
pub const DERIVE_KEY_FULL_CTX: &str = "NNCPE\x00\x00\x06 FULL";
pub const DERIVE_KEY_SIZE_CTX: &str = "NNCPE\x00\x00\x06 SIZE"; 
pub const DERIVE_KEY_PAD_CTX: &str = "NNCPE\x00\x00\x06 PAD";


/// Padding buffer size for streaming
pub const PAD_BUFFER_SIZE: usize = 8192;

/// MTH (Merkle Tree Hash) block size
pub const MTH_BLOCK_SIZE: usize = 128 * 1024;

/// MTH leaf key (actual values from Go NNCP)
pub const MTH_LEAF_KEY: [u8; 32] = [
    0xe1, 0x8b, 0xcc, 0xbb, 0x41, 0xcb, 0x5a, 0x11, 0x10, 0x51, 0x4f, 0xe5, 0x0d, 0x85, 0xea, 0x75,
    0x0f, 0x3d, 0x56, 0xf6, 0x23, 0x8c, 0x12, 0xac, 0x84, 0xee, 0x27, 0x36, 0xd1, 0xf4, 0x8b, 0x0b
];

/// MTH node key (actual values from Go NNCP)
pub const MTH_NODE_KEY: [u8; 32] = [
    0xda, 0xa8, 0xf8, 0x00, 0xd8, 0x26, 0xa1, 0xc1, 0x5a, 0x23, 0x31, 0x7c, 0x46, 0x97, 0xf2, 0x83,
    0x76, 0x12, 0x53, 0xe8, 0xa0, 0x5e, 0x93, 0x07, 0x4e, 0xad, 0xf0, 0xed, 0x3e, 0x2d, 0x68, 0xa9
];
