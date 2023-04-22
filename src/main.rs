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
    let b32_alph = RFC4648 { padding: true };
    println!("Generating ed25519 keypair...");
    let key_pair = KeyPair::from_seed(Seed::generate());
    let enc_keypair_pub = encode(b32_alph, &key_pair.pk.as_ref());
    println!("Encoded public key: {enc_keypair_pub:?}");
    println!("{key_pair:?}");
    println!("Creating nacl box keypair (exchpub and exchprv)...");
    let nacl_secret_key = SecretKey::generate(&mut OsRng);
    println!("Created private key {nacl_secret_key:?}");
    let nacl_pubkey_bytes = nacl_secret_key.public_key().as_bytes().clone();
}
