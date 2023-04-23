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

struct LocalNNCPNode {
    id: [u8; 32],
    exchpub: [u8; 32],
    exchprv: [u8; 32],
    signpub: [u8; 32],
    signprv: [u8; 32],
    noisepub: [u8; 32],
    noiseprv: [u8; 32],
}

// first, let's make an ed25519 keypair.
fn main() {
    let b32_alph = RFC4648 { padding: false };
    println!("Generating ed25519 keypair...");
    let sign_keypair = KeyPair::from_seed(Seed::generate());
    let encoded_ed_pub = encode(b32_alph, &sign_keypair.pk.as_ref());
    let encoded_ed_prv = encode(b32_alph, &sign_keypair.sk.as_ref());
    println!("Encoded public key: {encoded_ed_pub:?}");
    println!("Encoded ed private key: {encoded_ed_prv:?}");
    println!("Creating nacl box keypair (exchpub and exchprv)...");
    let nacl_secret_key = SecretKey::generate(&mut OsRng);
    let nacl_prv_bytes = nacl_secret_key.as_bytes();
    let nacl_pubkey_bytes = nacl_secret_key.public_key().as_bytes().clone();
    let encoded_nacl_pub = encode(b32_alph, &nacl_pubkey_bytes);
    let encoded_nacl_prv = encode(b32_alph, nacl_prv_bytes);
    println!("exchpub: {encoded_nacl_pub}");
    println!("exchprv: {encoded_nacl_prv}");
    let nb: snow::Builder = Builder::new(PATTERN.parse().unwrap());
    let noise_keypair = nb.generate_keypair().unwrap();

    // Now we encode .public and .private into base32 like above
    let encoded_noise_pub = encode(b32_alph, &noise_keypair.public);
    let encoded_noise_prv = encode(b32_alph, &noise_keypair.private);
    println!("noisepub: {encoded_noise_pub}");
    println!("noiseprv: {encoded_noise_prv}");
    // Node ID is blake2s256 hash of the signing public key (ed25519)
    let mut hasher: Blake2s256 = Blake2s256::new();
    hasher.update(&sign_keypair.pk.as_ref());
    let node_id = hasher.finalize();
    let encoded_node_id = encode(b32_alph, node_id.as_ref());
    println!("Node ID: {encoded_node_id}");
}
