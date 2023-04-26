/// a full NNCP node, likely our own

use crate::constants;
use blake2::{Blake2s256, Digest};
use crypto_box::aead::OsRng;
use crypto_box::SecretKey;
use ed25519_compact::KeyPair;
use ed25519_compact::Seed;
use snow::Builder;

pub struct LocalNNCPNode {
    /// Node ID
    pub id: [u8; 32],
    /// exchange private key
    pub exchprv: crypto_box::SecretKey,
    /// Signing key (node ID derived from hash of public key)
    pub signing_kp: ed25519_compact::KeyPair,
    /// Noise protocol keypair, used for nncp sync protocol
    pub noise_kp: snow::Keypair,
}
impl LocalNNCPNode {
    /// Generate a new local NNCP node, including keypairs for exchange, signing and the online sync protocol
    pub fn generate () -> Self {
        let sign_keypair = KeyPair::from_seed(Seed::generate());
        let nacl_secret_key = SecretKey::generate(&mut OsRng);
        let nb: snow::Builder = Builder::new(constants::NOISE_PROTO_PATTERN.parse().unwrap());
        let noise_keypair = nb.generate_keypair().unwrap();
        // Node ID is blake2s256 hash of the signing public key (ed25519)
        let mut hasher: Blake2s256 = Blake2s256::new();
        hasher.update(&sign_keypair.pk.as_ref());
        let node_id: [u8; 32] = hasher.finalize().try_into().unwrap();
        LocalNNCPNode {
            id: node_id,
            exchprv: nacl_secret_key,
            signing_kp: sign_keypair,
            noise_kp: noise_keypair,
        }
    }
}