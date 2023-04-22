#! nk - an nncp key generation tool

use base32::{encode, Alphabet};
use base32::Alphabet::RFC4648;
use crypto_box::aead::OsRng;
use crypto_box::aead::consts::True;
use crypto_box::{PublicKey, SecretKey};
use ed25519_compact::KeyPair;
use ed25519_compact::Seed;

// first, let's make an ed25519 keypair.
fn main() {
    let b32_alph = RFC4648 { padding: false };
    println!("Generating ed25519 keypair...");
    let key_pair = KeyPair::from_seed(Seed::generate());
    let encoded_ed_pub = encode(b32_alph, &key_pair.pk.as_ref());
    let encoded_ed_prv = encode(b32_alph, &key_pair.sk.as_ref());
    println!("Encoded public key: {encoded_ed_pub:?}");
    println!("Encoded ed private key: {encoded_ed_prv:?}");
    println!("Creating nacl box keypair (exchpub and exchprv)...");
    let nacl_secret_key = SecretKey::generate(&mut OsRng);
    let nacl_prv_bytes = nacl_secret_key.as_bytes();
    let nacl_pubkey_bytes = nacl_secret_key.public_key().as_bytes().clone();
    let encoded_nacl_pub = encode(b32_alph, &nacl_pubkey_bytes);
    let encoded_nacl_prv = encode(b32_alph, nacl_prv_bytes);
    println!("exchpub: {encoded_nacl_pub}");
    println!("excprv: {encoded_nacl_prv}");
}
