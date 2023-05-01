/// a full NNCP node, likely our own
use crate::constants;
// use blake2::Blake2s;
use anyhow::Error;
use blake2::digest::Digest;
use blake2::Blake2s256;
use crypto_box::aead::OsRng;
use crypto_box::SecretKey;
use crypto_box::PublicKey;
use ed25519_compact::KeyPair;
use ed25519_compact::Seed;
use snow::Builder;

pub struct LocalNNCPNode {
    /// exchange private key
    pub exchprv: crypto_box::SecretKey,
    /// Signing key (node ID derived from hash of public key)
    pub signing_kp: ed25519_compact::KeyPair,
    /// Noise protocol keypair, used for nncp sync protocol
    pub noise_kp: snow::Keypair,
}
impl LocalNNCPNode {
    pub fn new(&signing_kp_bytes: [u8; ed25519_compact::KeyPair::BYTES], exch_kp_bytes: [u8; 32]) -> Result<Self, Error> {
        let signing_kp = ed25519_compact::KeyPair::from_slice(&signing_kp_bytes)?;
        let exch_kp = crypto_box::PublicKey::from(exch_kp_bytes);
        
    }

    /// Generate a new local NNCP node, including keypairs for exchange, signing and the online sync protocol
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
    /// Id is blake2s256 hash of the public signing keypair.
    pub fn id(&self) -> [u8; 32] {
        let mut hasher: Blake2s256 = Blake2s256::new();
        hasher.update(&self.signing_kp.pk.as_ref());
        let id: [u8; 32] = hasher.finalize().try_into().unwrap();
        id
    }
}
