use super::{Context};
use anyhow::Error;
use base32::{encode, Alphabet::RFC4648};
use nncp_rs::nncp::LocalNNCPNode;

/// Generate a local node and print its keys and ID to stdout (does not save to config)
pub fn generate_node(_ctx: Context) -> Result<(), Error> {
    // Generate a new node without saving it anywhere
    let node = LocalNNCPNode::generate();
    let b32_alph = RFC4648 { padding: false };
    let encoded_node_id = node.encoded_id();
    println!("Node ID: {encoded_node_id}");
    let encoded_ed_pub = encode(b32_alph, node.signing_kp.pk.as_ref());
    let encoded_ed_prv = encode(b32_alph, node.signing_kp.sk.as_ref());
    println!("Signing public key: {encoded_ed_pub}");
    println!("Signing secret key: {encoded_ed_prv}");
    let encoded_nacl_pub = encode(b32_alph, &node.exchprv.public_key().as_bytes().clone());
    let encoded_nacl_prv = encode(b32_alph, &node.exchprv.as_bytes().clone());
    println!("exchange public key: {encoded_nacl_pub}");
    println!("exchange secret key: {encoded_nacl_prv}");
    let encoded_noise_pub = encode(b32_alph, &node.noise_kp.public);
    let encoded_noise_prv = encode(b32_alph, &node.noise_kp.private);
    println!("noise public key: {encoded_noise_pub}");
    println!("noise secret key: {encoded_noise_prv}");
    Ok(())
}

pub fn print_local_node(ctx: Context, emojify: bool) {
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
