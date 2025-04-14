//! Magic numbers for NNCP
//!
//! This module defines the magic numbers used to identify different NNCP packet types.

/// Magic number structure
#[derive(Debug, Clone)]
pub struct Magic {
    /// 8-byte magic number
    pub bytes: [u8; 8],
    /// Human-readable name of the magic number
    pub name: &'static str,
    /// Version support information
    pub till: &'static str,
}

/// Magic number for NNCP packet v3
pub const NNCP_P_V3: Magic = Magic {
    bytes: *b"NNCPP/v3",
    name: "NNCP packet v3",
    till: "",
};

/// Magic number for NNCP encrypted blob v3
pub const NNCP_B_V3: Magic = Magic {
    bytes: *b"NNCPB/v3",
    name: "NNCP encrypted blob v3",
    till: "",
};
