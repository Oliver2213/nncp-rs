#! nk - an nncp key generation tool

use base32::encode;
use base32::Alphabet::RFC4648;

use nk::nncp::LocalNNCPNode;

fn main() {
    let node: LocalNNCPNode = LocalNNCPNode::generate();
    let b32_alph = RFC4648 { padding: false };
    let build_info = build_info::format!("Built at {} with {}", $.timestamp, $.compiler);
    println!("{build_info}");
    let encoded_node_id = encode(b32_alph, node.id.as_ref());
    println!("Node ID: {encoded_node_id}");
    let encoded_ed_pub = encode(b32_alph, &node.signing_kp.pk.as_ref());
    let encoded_ed_prv = encode(b32_alph, &node.signing_kp.sk.as_ref());
    println!("Encoded public key: {encoded_ed_pub}");
    println!("Encoded ed private key: {encoded_ed_prv}");
    let encoded_nacl_pub = encode(b32_alph, &node.exchprv.public_key().as_bytes().clone());
    let encoded_nacl_prv = encode(b32_alph, &node.exchprv.as_bytes().clone());
    println!("exchpub: {encoded_nacl_pub}");
    println!("exchprv: {encoded_nacl_prv}");
    let encoded_noise_pub = encode(b32_alph, &node.noise_kp.public);
    let encoded_noise_prv = encode(b32_alph, &node.noise_kp.private);
    println!("noisepub: {encoded_noise_pub}");
    println!("noiseprv: {encoded_noise_prv}");
}