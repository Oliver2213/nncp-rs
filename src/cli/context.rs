//! Context related to a command invocation

use super::config::{DiskConfig, LocalNodeDiskConfig};
use anyhow::Context as anyhow_context;
use anyhow::{anyhow, Error};
use base32::{decode, Alphabet::RFC4648};
use log::{debug, error, info, trace, warn};
use nncp_rs::nncp::LocalNNCPNode;
use std::path::Path;
use std::path::PathBuf;

/// Related context for nncp operations: config, spool, node keys, oh my!
/// Gets passed to every command function.
/// Essentially, this is our runtime config.
pub struct Context {
    /// Raw configuration structure.
    pub config: Option<DiskConfig>,
    /// Path to our configuration file
    pub config_path: PathBuf,
    /// Path to our log file
    pub log_path: PathBuf,
    /// Path to our node's spool directory
    pub spool_path: PathBuf,
    /// Our local node, ready to use
    pub local_node: Option<LocalNNCPNode>,
}

impl ::std::default::Default for Context {
    /// Returns a default command context, using default, user-local directories.
    /// Paths for the config file, spool directory and log file are set.
    fn default() -> Self {
        let config_path = confy::get_configuration_file_path("nncp-rs", "nncp").unwrap();
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
            local_node: None,
        }
    }
}

impl Context {
    /// Create an empty context, specifying paths for the config, spool and log
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
            local_node: None,
        }
    }

    /// Load the config from `config_path` and parse it, setting this context appropriately
    /// Returns any errors encountered in opening or parsing the config file or parsing node keys.
    pub fn load_config(&mut self) -> Result<(), Error> {
        debug!("Loading config");
        debug!("Config path: {}", &self.config_path.display());
        let config: DiskConfig =
            confy::load_path(&self.config_path).context("couldn't load nncp configuration")?;
        self.set_local_node(&config.localnode);
        trace!("Created and stored local node on context");
        self.config = Some(config);
        debug!("Set up context");
        Ok(())
    }

    pub fn set_local_node(&mut self, node: &LocalNodeDiskConfig) -> Result<(), Error> {
        let b32_alph = RFC4648 { padding: false };
        // parse our node's keys into an instance we can use:
        let signpub_b32 = decode(b32_alph, &node.signpub);
        let signpriv_b32 = decode(b32_alph, &node.signpriv);
        if signpub_b32.is_none() || signpriv_b32.is_none() {
            error!("Failed to base32 decode signing public or private key.");
            return Err(anyhow!("Unable to parse signing keys as valid base32"));
        }
        let _signpub_bytes: [u8; 32] = match signpub_b32.unwrap().try_into() {
            Ok(pk) => pk,
            Err(e) => return Err(anyhow!("Public signing key isn't 32 bytes long!")),
        };
        let signpriv_bytes: [u8; 64] = match signpriv_b32.unwrap().try_into() {
            Ok(sk) => sk,
            Err(e) => {
                return Err(anyhow!(
                    "Signing private key isn't 32 bytes long; error={e:?}"
                ))
            }
        };
        trace!("Parsed signing public and private keys into bytes");
        let exchpub_b32 = decode(b32_alph, &node.exchpub);
        let exchpriv_b32 = decode(b32_alph, &node.exchpriv);
        trace!("Decoded exchange keys from base32");
        if exchpub_b32.is_none() || exchpriv_b32.is_none() {
            error!("Unable to parse exchange keys as base 32");
            return Err(anyhow!("Unable to parse exchange keys as base32"));
        }
        let _exchpub: [u8; 32] = match exchpub_b32.unwrap().try_into() {
            Ok(b) => b,
            Err(e) => return Err(anyhow!("Exchange secret key was incorrect size")),
        };
        trace!("Parsed exchpub into bytes");
        let exchpriv_bytes: [u8; 32] = match exchpriv_b32.unwrap().try_into() {
            Ok(p) => p,
            Err(e) => return Err(anyhow!("exchange secret key was incorrect size")),
        };
        trace!("Parsed exchpriv into bytes");
        let noisepub_b32 = decode(b32_alph, &node.noisepub);
        let noisepriv_b32 = decode(b32_alph, &node.noiseprv);
        if noisepub_b32.is_none() || noisepriv_b32.is_none() {
            error!("Unable to parse noise protocol keys as base32");
            return Err(anyhow!("Unable to parse noise protocol keys as base32"));
        }
        let our_node = LocalNNCPNode::new(
            signpriv_bytes,
            exchpriv_bytes,
            noisepriv_b32.unwrap(),
            noisepub_b32.unwrap(),
        )?;
        self.local_node = Some(our_node);
        Ok(())
    }
    
    /// Given a number of bytes, return if the disk our spool directory is mounted on has that much free space
    pub fn enough_spool_space(&self, size: u64) -> Result<bool, Error> {
        // Determine how much space is free on spool-holding-disk
        let available = fs2::available_space(&self.spool_path)?;
        Ok(available <= size)
    }
}
