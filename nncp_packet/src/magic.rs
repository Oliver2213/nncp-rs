//! Magic numbers for NNCP packet identification
//!
//! These magic numbers are used to identify different types of NNCP packets
//! and their versions.

/// Magic number for NNCP packet identification
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Magic {
    /// 8-byte magic number
    pub bytes: [u8; 8],
    /// Human-readable name of the magic number
    pub name: &'static str,
    /// Version support information
    pub till: &'static str,
}

impl Magic {
    /// Create a new Magic with the given bytes, name, and support information
    pub const fn new(bytes: [u8; 8], name: &'static str, till: &'static str) -> Self {
        Self { bytes, name, till }
    }

    /// Returns an error indicating this format is too old and unsupported
    pub fn too_old(&self) -> String {
        format!("{} format is unsupported (used till {})", self.name, self.till)
    }
}

// Plain packet magic numbers
pub const NNCP_P_V1: Magic = Magic::new(
    *b"NNCPP\0\0\x01",
    "NNCPPv1 (plain packet v1)",
    "2.0",
);

pub const NNCP_P_V2: Magic = Magic::new(
    *b"NNCPP\0\0\x02",
    "NNCPPv2 (plain packet v2)",
    "4.1",
);

pub const NNCP_P_V3: Magic = Magic::new(
    *b"NNCPP\0\0\x03",
    "NNCPPv3 (plain packet v3)",
    "now",
);

// Area packet magic numbers
pub const NNCP_A_V1: Magic = Magic::new(
    *b"NNCPA\0\0\x01",
    "NNCPAv1 (area packet v1)",
    "now",
);

// EBlob magic numbers
pub const NNCP_B_V1: Magic = Magic::new(
    *b"NNCPB\0\0\x01",
    "NNCPBv1 (EBlob v1)",
    "1.0",
);

pub const NNCP_B_V2: Magic = Magic::new(
    *b"NNCPB\0\0\x02",
    "NNCPBv2 (EBlob v2)",
    "3.4",
);

pub const NNCP_B_V3: Magic = Magic::new(
    *b"NNCPB\0\0\x03",
    "NNCPBv3 (EBlob v3)",
    "now",
);

// Multicast discovery magic numbers
pub const NNCP_D_V1: Magic = Magic::new(
    *b"NNCPD\0\0\x01",
    "NNCPDv1 (multicast discovery v1)",
    "now",
);

// Encrypted packet magic numbers
pub const NNCP_E_V1: Magic = Magic::new(
    *b"NNCPE\0\0\x01",
    "NNCPEv1 (encrypted packet v1)",
    "0.12",
);

pub const NNCP_E_V2: Magic = Magic::new(
    *b"NNCPE\0\0\x02",
    "NNCPEv2 (encrypted packet v2)",
    "1.0",
);

pub const NNCP_E_V3: Magic = Magic::new(
    *b"NNCPE\0\0\x03",
    "NNCPEv3 (encrypted packet v3)",
    "3.4",
);

pub const NNCP_E_V4: Magic = Magic::new(
    *b"NNCPE\0\0\x04",
    "NNCPEv4 (encrypted packet v4)",
    "6.6.0",
);

pub const NNCP_E_V5: Magic = Magic::new(
    *b"NNCPE\0\0\x05",
    "NNCPEv5 (encrypted packet v5)",
    "7.7.0",
);

pub const NNCP_E_V6: Magic = Magic::new(
    *b"NNCPE\0\0\x06",
    "NNCPEv6 (encrypted packet v6)",
    "now",
);

// Sync protocol magic numbers
pub const NNCP_S_V1: Magic = Magic::new(
    *b"NNCPS\0\0\x01",
    "NNCPSv1 (sync protocol v1)",
    "now",
);

// Chunked meta magic numbers
pub const NNCP_M_V1: Magic = Magic::new(
    *b"NNCPM\0\0\x01",
    "NNCPMv1 (chunked .meta v1)",
    "6.6.0",
);

pub const NNCP_M_V2: Magic = Magic::new(
    *b"NNCPM\0\0\x02",
    "NNCPMv2 (chunked .meta v2)",
    "now",
);

/// NNCP bundle prefix
pub const NNCP_BUNDLE_PREFIX: &str = "NNCP";
