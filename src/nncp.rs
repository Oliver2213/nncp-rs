//! nncp library, containing structures for a local node, remote node, etc

use crate::constants;
use anyhow::Error;
use base32::{encode, Alphabet::RFC4648};

use blake2::{digest::consts::U32, Blake2b, Digest};
use crypto_box::aead::OsRng;
use crypto_box::SecretKey;
use ed25519_compact::KeyPair;
use ed25519_compact::Seed;
use snow::Builder;

/// A blake2b hasher with a compile-time output size of 32 bytes
pub type Blake2b32Hasher = Blake2b<U32>;
/// An NNCP node's ID, as bytes
pub type NodeID = [u8; 32];

/// a full NNCP node, likely our own
pub struct LocalNNCPNode {
    /// exchange private key
    pub exchprv: crypto_box::SecretKey,
    /// Signing key (node ID derived from hash of this public key)
    pub signing_kp: ed25519_compact::KeyPair,
    /// Noise protocol keypair, used for nncp sync protocol
    pub noise_kp: snow::Keypair,
}

#[derive(Clone)]
pub struct RemoteNNCPNode {
    /// exchange public key
    pub exchpub: crypto_box::PublicKey,
    /// Signing public key
    pub signpub: ed25519_compact::PublicKey,
    /// Optional noise protocol public key, for synchronous online exchanges
    /// If we don't have this, packets from this node can only be delivered asynchronously; we don't know the noise key to use the internet for real-time communication.
    pub noisepub: Option<Vec<u8>>,
}

impl LocalNNCPNode {
    /// Create a local nncp node given it's secret keys. Useful when loading from a config file.
    /// Typically done after you've generated one with generate-node or the go implementation.
    pub fn new(
        signing_kp_bytes: [u8; 64],
        exch_priv_bytes: [u8; 32],
        noise_priv_bytes: Vec<u8>,
        noise_pub_bytes: Vec<u8>,
    ) -> Result<Self, Error> {
        let signing_kp = ed25519_compact::KeyPair::from_slice(&signing_kp_bytes)?;
        let exch_sk = crypto_box::SecretKey::from(exch_priv_bytes);
        let noise_kp = snow::Keypair {
            private: noise_priv_bytes,
            public: noise_pub_bytes,
        };
        let node = LocalNNCPNode {
            exchprv: exch_sk,
            signing_kp,
            noise_kp,
        };
        Ok(node)
    }

    /// Generate a new local NNCP node, including keypairs for exchange, signing and the online sync protocol
    /// An nncp node we fully control (E.G. can authenticate as, receive packets as, etc)
    pub fn generate() -> Self {
        let sign_keypair = KeyPair::from_seed(Seed::generate());
        let nacl_secret_key = SecretKey::generate(&mut OsRng);
        let nb: snow::Builder = Builder::new(constants::NOISE_PROTO_PATTERN.parse().unwrap());
        let noise_keypair = nb.generate_keypair().unwrap();
        LocalNNCPNode {
            exchprv: nacl_secret_key,
            signing_kp: sign_keypair,
            noise_kp: noise_keypair,
        }
    }

    /// Returns this node's ID as bytes.
    /// Computed from hash of signing public key.
    pub fn id(&self) -> NodeID {
        let mut hasher = Blake2b32Hasher::new();
        hasher.update(self.signing_kp.pk.as_ref());
        let id: [u8; 32] = hasher.finalize().try_into().expect(
            "error converting node ID to 32 byte hash - has the output size of hashes changed?",
        );
        id
    }

    pub fn encoded_id(&self) -> String {
        let b32_alph = RFC4648 { padding: false };
        encode(b32_alph, &self.id())
    }
}

impl RemoteNNCPNode {
    pub fn new(
        signpub_bytes: [u8; 32],
        exchpub_bytes: [u8; 32],
        noisepub_bytes: Option<Vec<u8>>,
    ) -> Result<Self, Error> {
        let signpub = ed25519_compact::PublicKey::from_slice(&signpub_bytes)?;
        let exchpub = crypto_box::PublicKey::from(exchpub_bytes);
        let noisepub = noisepub_bytes;
        Ok(RemoteNNCPNode {
            signpub,
            exchpub,
            noisepub,
        })
    }
    /// Returns this node's ID as bytes.
    /// Computed from hash of signing public key.
    pub fn id(&self) -> NodeID {
        let mut hasher = Blake2b32Hasher::new();
        hasher.update(self.signpub.as_ref());
        let id: [u8; 32] = hasher.finalize().try_into().expect(
            "error converting remote node ID to 32 byte hash - has the output size of hashes changed?",
        );
        id
    }

    pub fn encoded_id(&self) -> String {
        let b32_alph = RFC4648 { padding: false };
        encode(b32_alph, &self.id())
    }
}
