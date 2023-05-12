use super::{Cli, Context};
use anyhow::Error;
use base32::{encode, Alphabet::RFC4648};
use dialoguer::Confirm;
use nncp_rs::nncp::LocalNNCPNode;
use std::fs::remove_file;
use log::debug;

/// Generate a local node and psave it, printing its keys and ID to stdout
pub fn generate_node(ctx: Context) -> Result<(), Error> {
    // So this command is nice and short: by the time it runs, a default config (including a local node) has been generated and saved, either in the default location, or specified by env var or command line option
    let node: LocalNNCPNode;
    if ctx.config_existed {
        debug!("Config exists; prompting user y/n regenerate");
        if Confirm::new().with_prompt("You already have a configuration file generated. Are you sure you want to delete it and create a new one?").interact()? {
            remove_file(&ctx.config_path)?;
            println!("Deleted existing config");
            // Keep the same log, spool and config paths, as they were set potentially from env vars or the commandline
            let mut new_ctx = Context::new(ctx.config_path, ctx.log_path, ctx.spool_path);
            new_ctx.load_config()?;
            node = new_ctx.local_node.expect("No default node was created with config");
            println!("Generated new config at {}", &new_ctx.config_path.display());
        } else {
            println!("Config recreation aborted.");
            return Ok(());
        }
    } else {
        // No config existed before; we just wrote one by loading the context before getting here
        node = ctx.local_node.expect("default config did not include a generated local node");
        println!("Generated new config at {}", &ctx.config_path.display());
    }
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
