use base32::{encode, Alphabet::RFC4648};
use nncp_rs::nncp::LocalNNCPNode;
use serde::{Deserialize, Serialize};
use std::convert::From;
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
/// Our main config struct - what gets read from and written to disk
pub struct Config {
    /// Our local node's config
    localnode: LocalNodeConfig,
    /// Path to our log file
    log: PathBuf,
    /// Path to our local node's spool directory
    spool: PathBuf,
}

impl ::std::default::Default for Config {
    /// Create a default configuration.
    /// Creates a node keypair and sets default paths for the log file and spool directory
    fn default() -> Self {
        let ctx = super::Context::default();
        let new_node = LocalNNCPNode::generate();
        Config {
            localnode: new_node.into(),
            log: ctx.log_path,
            spool: ctx.spool_path,
        }
    }
}

/// Config representation of our local node.
#[derive(Serialize, Deserialize)]
pub struct LocalNodeConfig {
    /// Exchange public key
    exchpub: String,
    /// Exchange private key
    exchpriv: String,
    /// Public signing key
    signpub: String,
    /// Secret signing key
    signpriv: String,
    /// Public noise protocol key
    noisepub: String,
    /// Secret noise protocol key
    noiseprv: String,
}

impl From<LocalNNCPNode> for LocalNodeConfig {
    /// Converts a `LocalNNCPNode` to a serialized, base-32 encoded set of values in a node config
    fn from(node: LocalNNCPNode) -> Self {
        let b32_alph = RFC4648 { padding: false };
        let encoded_ed_pub = encode(b32_alph, node.signing_kp.pk.as_ref());
        let encoded_ed_prv = encode(b32_alph, node.signing_kp.sk.as_ref());
        let encoded_nacl_pub = encode(b32_alph, &node.exchprv.public_key().as_bytes().clone());
        let encoded_nacl_prv = encode(b32_alph, &node.exchprv.as_bytes().clone());
        let encoded_noise_pub = encode(b32_alph, &node.noise_kp.public);
        let encoded_noise_prv = encode(b32_alph, &node.noise_kp.private);
        LocalNodeConfig {
            exchpub: encoded_nacl_pub,
            exchpriv: encoded_nacl_prv,
            signpub: encoded_ed_pub,
            signpriv: encoded_ed_prv,
            noisepub: encoded_noise_pub,
            noiseprv: encoded_noise_prv,
        }
    }
}
