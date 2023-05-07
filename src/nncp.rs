/// a full NNCP node, likely our own
use crate::constants;
// use blake2::Blake2s;
use anyhow::Error;
use blake2::digest::Digest;
use blake2::Blake2s256;
use crypto_box::aead::OsRng;

use crypto_box::SecretKey;
use ed25519_compact::KeyPair;
use ed25519_compact::Seed;
use snow::Builder;

pub struct LocalNNCPNode {
    /// exchange private key
    pub exchprv: crypto_box::SecretKey,
    /// Signing key (node ID derived from hash of this public key)
    pub signing_kp: ed25519_compact::KeyPair,
    /// Noise protocol keypair, used for nncp sync protocol
    pub noise_kp: snow::Keypair,
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
    pub fn id(&self) -> [u8; 32] {
        let mut hasher: Blake2s256 = Blake2s256::new();
        hasher.update(self.signing_kp.pk.as_ref());
        let id: [u8; 32] = hasher.finalize().try_into().unwrap();
        id
    }
}
