#! nk - an nncp key generation tool

use base32::encode;
use base32::Alphabet::RFC4648;
use blake2::{Blake2s256, Digest};
use crypto_box::aead::OsRng;
use crypto_box::SecretKey;
use ed25519_compact::KeyPair;
use ed25519_compact::Seed;
use snow::Builder;

/// the noise pattern used by nncp
static PATTERN: &'static str = "Noise_IK_25519_ChaChaPoly_BLAKE2b";

/// a full NNCP node, likely our own
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
    fn generate () -> Self {
        let sign_keypair = KeyPair::from_seed(Seed::generate());
        let nacl_secret_key = SecretKey::generate(&mut OsRng);
        let nacl_prv_bytes = nacl_secret_key.as_bytes().clone();
        let nacl_pubkey_bytes = nacl_secret_key.public_key().as_bytes().clone();
        let nb: snow::Builder = Builder::new(PATTERN.parse().unwrap());
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

fn main() {
    let node: LocalNNCPNode = LocalNNCPNode::generate();
    let b32_alph = RFC4648 { padding: false };
    let build_info = build_info::format!("Built at {} with {}", $.timestamp, $.compiler);
    println!("{build_info}");
    let encoded_node_id = encode(b32_alph, node.id.as_ref());
    println!("Node ID: {encoded_node_id}");
    let encoded_ed_pub = encode(b32_alph, &node.signing_kp.pk.as_ref());
    let encoded_ed_prv = encode(b32_alph, &node.signing_kp.sk.as_ref());
    println!("Encoded public key: {encoded_ed_pub:?}");
    println!("Encoded ed private key: {encoded_ed_prv:?}");
    let encoded_nacl_pub = encode(b32_alph, &node.exchprv.public_key().as_bytes().clone());
    let encoded_nacl_prv = encode(b32_alph, &node.exchprv.as_bytes().clone());
    println!("exchpub: {encoded_nacl_pub}");
    println!("exchprv: {encoded_nacl_prv}");
    let encoded_noise_pub = encode(b32_alph, &node.noise_kp.public);
    let encoded_noise_prv = encode(b32_alph, &node.noise_kp.private);
    println!("noisepub: {encoded_noise_pub}");
    println!("noiseprv: {encoded_noise_prv}");
}