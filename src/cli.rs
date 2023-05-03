//! NNCP subcommands

use crate::nncp::LocalNNCPNode;
use base32::encode;
use base32::Alphabet::RFC4648;
use clap::Parser;
use clap::Subcommand;
use std::path::PathBuf;
// use crate::cli;
use crate::constants;

#[derive(Subcommand)]
#[deny(missing_docs)]
/// all NNCP subcommands
pub enum Commands {
    /// Generates a new node and prints it's base 32 encoded keys to stdout
    GenerateNode,
}

#[derive(Parser)]
#[command(author, version, about, long_about = &constants::LONG_ABOUT)]
#[command(propagate_version = true)]
/// Our command-line interface
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    /// NNCP configuration file
    #[arg(short, long, value_name = "CONFIG_FILE")]
    pub config: Option<PathBuf>,
}

/// Generate a local node and print its keys and ID to stdout
pub fn generate_node() {
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
