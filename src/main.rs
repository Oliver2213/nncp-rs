//! nncp-rs - node to node copy tools

use clap::Parser;
mod cli;
use anyhow::Error;


fn main() -> Result<(), Error> {
    let config_path = confy::get_configuration_file_path("nncp-rs", None)?;
    let ctx = cli::Context::default();
    println!("Spool path: {}", &ctx.spool_path.display());
    println!("Config: {:?}", &config_path);
    if config_path.exists() == false {
        println!("Config doesn't exist.");
    }
    let cli = cli::Cli::parse();
    match &cli.command {
        cli::Commands::GenerateNode => cli::node::generate_node(),
    }
    Ok(())
}
