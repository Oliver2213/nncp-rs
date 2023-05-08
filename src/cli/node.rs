use super::Context;
use base32::{encode, Alphabet::RFC4648};
use nncp_rs::nncp::LocalNNCPNode;

/// Generate a local node and print its keys and ID to stdout
pub fn generate_node(_ctx: Context) {
    let node: LocalNNCPNode = LocalNNCPNode::generate();
    let b32_alph = RFC4648 { padding: false };
    let encoded_node_id = encode(b32_alph, &node.id());
    println!("Node ID: {encoded_node_id}");
    let encoded_ed_pub = encode(b32_alph, node.signing_kp.pk.as_ref());
    let encoded_ed_prv = encode(b32_alph, node.signing_kp.sk.as_ref());
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

pub fn PrintLocalNode(ctx: Context, emojify: bool) {
    match ctx.local_node {
        Some(n) => {
            let id = n.encoded_id();
            println!("Your node ID: {}", &id);
            if emojify {
                let emoji_id = emoji256::encode(&id);
                println!("Also known as {}", emoji_id);
            }
        }
        None => println!("No config is loaded; local node information is unknown."),
    }
}
