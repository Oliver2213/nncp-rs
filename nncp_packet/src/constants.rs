//! Constants used throughout the NNCP packet implementation

/// Encryption block size (128 KB)
pub const ENC_BLK_SIZE: usize = 128 * 1024;

/// Size of MTH hash in bytes
pub const MTH_SIZE: usize = 32;

/// NNCP bundle prefix
pub const NNCP_BUNDLE_PREFIX: &str = "NNCP";

/// Maximum size of a path in a packet
pub const MAX_PATH_SIZE: usize = (1 << 8) - 1;
