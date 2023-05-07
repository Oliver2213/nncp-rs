//! Context related to a command invocation

use std::path::Path;
use std::path::PathBuf;
use anyhow::Error;
use anyhow::Context as anyhow_context;
use super::config::Config;
/// Related context for a command: config, spool, node keys, oh my!
/// Gets passed to every command function.
pub struct Context {
    config: Option<Config>,
    /// Path to our configuration file
    pub config_path: PathBuf,
    /// Path to our log file
    pub log_path: PathBuf,
    /// Path to our node's spool directory
    pub spool_path: PathBuf,
}

impl ::std::default::Default for Context {
    /// Returns a default command context, using default, user-local directories.
    /// Paths for the config file, spool directory and log file are set.
    fn default() -> Self {
        let config_path = confy::get_configuration_file_path("nncp-rs", None).unwrap();
        // Note: this structure (rs as tld, empty string as domain, app name as subdomain) is chosen to be the same as used by confy, which creates the path for the config - so they're all in the same place.
        let project_dir = directories::ProjectDirs::from("rs", "", "nncp")
            .expect("Unable to determine project directory");
        let data_path = project_dir.data_local_dir();
        let mut spool_path = PathBuf::from(&data_path);
        spool_path.push("spool");
        let mut log_path = PathBuf::from(data_path);
        log_path.push("nncp.log");
        
        Context {
            config: None,
            config_path,
            log_path,
            spool_path,
        }
    }
}

impl Context {
    fn new(
        config_path: impl AsRef<Path>,
        log_path: impl AsRef<Path>,
        spool_path: impl AsRef<Path>,
    ) -> Self {
        let config_path: PathBuf = config_path.as_ref().to_path_buf();
        let log_path: PathBuf = log_path.as_ref().to_path_buf();
        let spool_path: PathBuf = spool_path.as_ref().to_path_buf();
        Context {
            config: None,
            config_path,
            log_path,
            spool_path,
        }
    }

    /// Load the config given by config_path, saving it in this context.
    pub fn load_config (&mut self) -> Result<(), Error> {
        let config: Config = confy::load_path(&self.config_path).context("couldn't load nncp configuration")?;
        self.config = Some(config);
        Ok(())
    }
}