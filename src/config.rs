use std::path::PathBuf;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
/// Our main config struct
struct Config {
    /// Path to our log file
    log: PathBuf,
    /// Path to our local node's spool directory
    spool: PathBuf,
    
}

