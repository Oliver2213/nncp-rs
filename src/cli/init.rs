use super::{Context};
use anyhow::Error;
use dialoguer::{Confirm, Input};
use nncp_rs::nncp::LocalNNCPNode;
use std::fs::{create_dir_all, remove_file};
use std::path::PathBuf;
use log::debug;

/// Initialize NNCP configuration and spool directory
pub fn init(ctx: Context, directory: Option<PathBuf>, spool: Option<PathBuf>) -> Result<(), Error> {
    // Show defaults if no arguments provided
    if directory.is_none() && spool.is_none() {
        println!("Using default directories:");
        println!("  Config: {}", ctx.config_path.parent().unwrap_or_else(|| std::path::Path::new(".")).display());
        println!("  Spool:  {}", ctx.spool_path.display());
        println!();
    }

    // Handle directory option - update config path if provided
    let config_path = if let Some(ref dir) = directory {
        dir.join("nncp.toml") // or whatever the default config filename is
    } else {
        ctx.config_path.clone()
    };
    
    // Handle spool directory logic
    let spool_path = match (directory.as_ref(), spool.as_ref()) {
        (_, Some(spool_dir)) => spool_dir.clone(), // Explicit spool directory provided
        (Some(dir), None) => dir.join(".nncp-spool"), // Directory provided, use .nncp-spool inside it
        (None, None) => ctx.spool_path.clone(), // Use OS-specific default from context
    };

    // Check if config already exists at the target location
    let config_existed = config_path.exists();
    if config_existed {
        debug!("Config exists; prompting user y/n to recreate");
        if !Confirm::new()
            .with_prompt("You already have a configuration file. Are you sure you want to delete it and create a new one?")
            .interact()? 
        {
            println!("Initialization aborted.");
            return Ok(());
        }
        remove_file(&config_path)?;
        println!("Deleted existing config");
    }

    // Create new context with updated paths
    let mut new_ctx = Context::new(&config_path, &ctx.log_path, &spool_path);
    new_ctx.load_config()?;
    
    let node = new_ctx.local_node.expect("No default node was created with config");
    println!("Generated new config at {}", &new_ctx.config_path.display());
    
    // Handle spool directory - ask user if the determined path is okay
    let mut final_spool_path = new_ctx.spool_path.clone();
    
    // Ask user if the spool path is okay
    let spool_confirmed = Confirm::new()
        .with_prompt(&format!("Use spool directory: {}?", final_spool_path.display()))
        .interact()?;
    
    if !spool_confirmed {
        let new_spool: String = Input::new()
            .with_prompt("Enter new spool directory path")
            .interact()?;
        final_spool_path = PathBuf::from(new_spool);
        
        // Update context with new spool path
        new_ctx.spool_path = final_spool_path.clone();
        // TODO: Save updated config with new spool path
        // This would require access to the config saving functionality
    }
    
    // Create spool directory
    if !final_spool_path.exists() {
        create_dir_all(&final_spool_path)?;
        println!("Created spool directory: {}", final_spool_path.display());
    } else {
        println!("Spool directory already exists: {}", final_spool_path.display());
    }
    
    println!("NNCP initialization complete!");
    println!("Config file: {}", new_ctx.config_path.display());
    println!("Spool directory: {}", final_spool_path.display());
    println!("Node ID: {}", node.encoded_id());
    
    Ok(())
}
