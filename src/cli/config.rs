use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Serialize, Deserialize)]
/// Our main config struct - what gets read from and written to disk
pub struct Config {
    /// Path to our log file
    log: PathBuf,
    /// Path to our local node's spool directory
    spool: PathBuf,
}

impl ::std::default::Default for Config {
    fn default() -> Self {
        let ctx = super::Context::default();
        Config {
            log: ctx.log_path,
            spool: ctx.spool_path,
        }
    }
}

pub struct LocalNode {}
