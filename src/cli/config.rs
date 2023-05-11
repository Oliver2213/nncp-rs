//! Tool config structs and stuff

use base32::{encode, Alphabet::RFC4648};
use nncp_rs::nncp::LocalNNCPNode;
use nncp_rs::nncp::RemoteNNCPNode;
use serde::{Deserialize, Serialize};
use std::convert::From;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
/// Our main config struct - what gets read from and written to disk
/// Bytes (E.G. node IDs, keys, etc are base32 encoded)
pub struct DiskConfig {
    /// Path to our log file
    pub log: PathBuf,
    /// Path to our local node's spool directory
    pub spool: PathBuf,
    /// Our config format version, to deal with potential future changes in what we store in the config and how
    pub format_version: u8,
    /// Our local node's config
    pub localnode: LocalNodeDiskConfig,
}

impl ::std::default::Default for DiskConfig {
    /// Create a default configuration.
    /// Creates a node keypair and sets default paths for the log file and spool directory
    fn default() -> Self {
        let ctx = super::Context::default();
        let new_node = LocalNNCPNode::generate();
        DiskConfig {
            localnode: new_node.into(),
            log: ctx.log_path,
            spool: ctx.spool_path,
            format_version: 1,
        }
    }
}

/// Config representation of our local node.
#[derive(Serialize, Deserialize)]
pub struct LocalNodeDiskConfig {
    /// Exchange public key
    pub exchpub: String,
    /// Exchange private key
    pub exchpriv: String,
    /// Public signing key
    pub signpub: String,
    /// Secret signing key
    pub signpriv: String,
    /// Public noise protocol key
    pub noisepub: String,
    /// Secret noise protocol key
    pub noiseprv: String,
}

/// An nncp node we can communicate with
#[derive(Serialize, Deserialize)]
pub struct RemoteNodeDiskConfig {
    /// Public signing key
    pub signpub: String,
    /// Exchange public key
    pub exchpub: String,
    /// Public noise protocol key
    pub noisepub: Option<String>,
}

impl From<LocalNNCPNode> for LocalNodeDiskConfig {
    /// Converts a `LocalNNCPNode` to a serialized, base-32 encoded set of values in a node config
    fn from(node: LocalNNCPNode) -> Self {
        let b32_alph = RFC4648 { padding: false };
        let encoded_ed_pub = encode(b32_alph, node.signing_kp.pk.as_ref());
        let encoded_ed_prv = encode(b32_alph, node.signing_kp.sk.as_ref());
        let encoded_nacl_pub = encode(b32_alph, &node.exchprv.public_key().as_bytes().clone());
        let encoded_nacl_prv = encode(b32_alph, &node.exchprv.as_bytes().clone());
        let encoded_noise_pub = encode(b32_alph, &node.noise_kp.public);
        let encoded_noise_prv = encode(b32_alph, &node.noise_kp.private);
        LocalNodeDiskConfig {
            exchpub: encoded_nacl_pub,
            exchpriv: encoded_nacl_prv,
            signpub: encoded_ed_pub,
            signpriv: encoded_ed_prv,
            noisepub: encoded_noise_pub,
            noiseprv: encoded_noise_prv,
        }
    }
}

impl From<RemoteNNCPNode> for RemoteNodeDiskConfig {
    /// Converts a `RemoteNNCPNode` to it's disk / config format representation
    fn from(node: RemoteNNCPNode) -> Self {
        let b32_alph = RFC4648 { padding: false };
        let encoded_signpub = encode(b32_alph, node.signpub.as_ref());
        let encoded_exchpub = encode(b32_alph, &node.exchpub.as_bytes().clone());
        let encoded_noisepub: Option<String> = node.noisepub.map(|np| encode(b32_alph, &np));
        RemoteNodeDiskConfig {
            signpub: encoded_signpub,
            exchpub: encoded_exchpub,
            noisepub: encoded_noisepub,
        }
    }
}
