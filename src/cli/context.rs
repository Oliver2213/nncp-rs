//! Context related to a command invocation

use crate::cli::config::RemoteNodeDiskConfig;
use nncp_rs::constants::DEFAULT_CONFIG_FILENAME;

use super::config::{DiskConfig, LocalNodeDiskConfig};
use anyhow::Context as anyhow_context;
use anyhow::{anyhow, Error};
use base32::{decode, Alphabet::RFC4648};
use log::{debug, error, info, trace, warn};
use nncp_rs::nncp::{LocalNNCPNode, NodeID, RemoteNNCPNode};
use nncp_rs::NNCPError;
use std::collections::HashMap;
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
    /// Did our config exist before we created the context
    pub config_existed: bool,
    /// Path to our log file
    pub log_path: PathBuf,
    /// Path to our node's spool directory
    pub spool_path: PathBuf,
    /// Our local node, ready to use
    pub local_node: Option<LocalNNCPNode>,
    /// Hashmap of neighbor-nodes we know about, keyed by their ID
    pub neighbors: HashMap<NodeID, RemoteNNCPNode>,
    /// Mapping of neighbor friendly names to their 32-byte IDs
    pub neighbor_aliases: HashMap<String, NodeID>,
}

impl ::std::default::Default for Context {
    /// Returns a default command context, using default, user-local directories.
    /// Paths for the config file, spool directory and log file are set.
    fn default() -> Self {
        let (config_path, spool_path, log_path) = Context::default_paths();
        Context::new(config_path, log_path, spool_path)
    }
}

impl Context {
    /// Get default paths using user-specified data directory
    /// Returns (config_path, spool_path, log_path)
    fn default_paths() -> (PathBuf, PathBuf, PathBuf) {
        let project_dir = directories::ProjectDirs::from("", "", "nncp")
            .expect("Unable to determine project directory");
        let data_path = project_dir.data_local_dir();
        let mut config_path = PathBuf::from(&data_path);
        config_path.push(DEFAULT_CONFIG_FILENAME);
        let mut spool_path = PathBuf::from(&data_path);
        spool_path.push("spool");
        let mut log_path = PathBuf::from(data_path);
        log_path.push("nncp.log");
        (config_path, spool_path, log_path)
    }
    
    /// Get the default config directory as a string for clap defaults
    pub fn default_config_dir_string() -> String {
        let (config_path, _, _) = Self::default_paths();
        config_path.parent()
            .unwrap_or_else(|| std::path::Path::new("."))
            .display()
            .to_string()
    }
    
    /// Get the default spool directory as a string for clap defaults
    pub fn default_spool_dir_string() -> String {
        let (_, spool_path, _) = Self::default_paths();
        spool_path.display().to_string()
    }

    /// Create an empty context, specifying paths for the config, spool and log
    pub fn new(
        config_path: impl AsRef<Path>,
        log_path: impl AsRef<Path>,
        spool_path: impl AsRef<Path>,
    ) -> Self {
        let config_path: PathBuf = config_path.as_ref().to_path_buf();
        let log_path: PathBuf = log_path.as_ref().to_path_buf();
        let spool_path: PathBuf = spool_path.as_ref().to_path_buf();
        Context {
            config: None,
            config_existed: false,
            config_path,
            log_path,
            spool_path,
            local_node: None,
            neighbors: HashMap::new(),
            neighbor_aliases: HashMap::new(),
        }
    }

    /// Load the config from `config_path` and parse it, setting this context appropriately
    /// Returns any errors encountered in opening or parsing the config file or parsing node keys or neighbors
    pub fn load_config(&mut self) -> Result<(), Error> {
        debug!("Loading config");
        debug!("Config path: {}", &self.config_path.display());
        self.config_existed = self.config_path.exists();
        let config: DiskConfig =
            confy::load_path(&self.config_path).context("couldn't load nncp configuration")?;
        self.set_local_node(&config.localnode)?;
        trace!("Created and stored local node on context");
        self.set_neighbors(&config.neigh)?;

        self.config = Some(config);
        debug!("Set up context");
        Ok(())
    }

    /// Save the current config to `config_path`
    /// Returns any errors encountered in writing the config file
    pub fn save_config(&self) -> Result<(), Error> {
        debug!("Saving config");
        debug!("Config path: {}", &self.config_path.display());
        if let Some(ref config) = self.config {
            confy::store_path(&self.config_path, config).context("couldn't save nncp configuration")?;
            debug!("Config saved successfully");
        } else {
            return Err(anyhow!("No config to save"));
        }
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
            Err(_e) => return Err(anyhow!("Public signing key isn't 32 bytes long!")),
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
            Err(_e) => {
                error!("Exchange public key was incorrect size (must be 32 bytes)");
                return Err(anyhow!(
                    "The local node's exchange public key has incorrect size (must be 32 bytes)"
                ));
            }
        };
        trace!("Parsed exchpub into bytes");
        let exchpriv_bytes: [u8; 32] = match exchpriv_b32.unwrap().try_into() {
            Ok(p) => p,
            Err(_e) => {
                error!("Exchange secret key was incorrect size (must be 32 bytes)");
                return Err(anyhow!(
                    "The local node's exchange secret key has incorrect size (must be 32 bytes)"
                ));
            }
        };
        trace!("Parsed exchpriv into bytes");
        let noisepub_b32 = decode(b32_alph, &node.noisepub);
        let noisepriv_b32 = decode(b32_alph, &node.noiseprv);
        if noisepub_b32.is_none() || noisepriv_b32.is_none() {
            error!("Unable to parse local node's noise protocol keys as base32");
            return Err(anyhow!(
                "Unable to parse local node's noise protocol keys as base32"
            ));
        }
        let noisepub = noisepub_b32.unwrap();
        if noisepub.len() != 32 {
            error!("Noise public key isn't 32 bytes");
            return Err(anyhow!("Local node's noise public key isn't 32 bytes"));
        }
        let noiseprv = noisepriv_b32.unwrap();
        if noiseprv.len() != 32 {
            error!("Local node noise private key isn't 32 bytes");
            return Err(anyhow!("Local node's noise private key isn't 32 bytes"));
        }
        let our_node = LocalNNCPNode::new(signpriv_bytes, exchpriv_bytes, noiseprv, noisepub)?;
        self.local_node = Some(our_node);
        Ok(())
    }

    /// Given a number of bytes, return if the disk our spool directory is mounted on has that much free space
    pub fn enough_spool_space(&self, size: u64) -> Result<bool, Error> {
        // Determine how much space is free on spool-holding-disk
        let available = fs2::available_space(&self.spool_path)?;
        Ok(available <= size)
    }

    /// Given a friendly name and a remote node, add it as a known neighbor, mapping it's friendly name to ID for lookup
    /// Return whether we replaced an existing node with the same friendly name
    pub fn add_neighbor(&mut self, name: &String, neighbor: RemoteNNCPNode) -> bool {
        let mut replaced = false;
        let id = neighbor.id();
        self.neighbors.insert(id, neighbor);
        // Warn if we somehow replace an existing node keyed by the same friendly name
        match self.neighbor_aliases.insert(name.to_string(), id) {
            Some(old_id) => {
                warn!("Replacing neighbor node '{name}': was ID '{old_id:?}");
                replaced = true;
            },
            None => (),
        }
        replaced
    }

    /// Load all known neighbor nodes from config using two-pass loading
    /// 
    /// First pass: Create nodes without via resolution
    /// Second pass: Resolve via node names to NodeIDs after all nodes are loaded
    pub fn set_neighbors(
        &mut self,
        neighbors_config: &HashMap<String, RemoteNodeDiskConfig>,
    ) -> Result<(), Error> {
        // First pass: Create all nodes without via resolution
        // Store via strings for second pass
        let mut via_strings: HashMap<nncp_rs::nncp::NodeID, Vec<String>> = HashMap::new();
        
        for (name, node_config) in neighbors_config {
            trace!("First pass: Parsing neighbor-node '{}'", &name);
            let neighbor = Context::parse_remote_node_without_via(node_config)
                .context(format!("Parsing neighbor-node '{}'", &name))?;
            
            // Store via strings for second pass resolution
            if !node_config.via.is_empty() {
                via_strings.insert(neighbor.id(), node_config.via.clone());
            }
            
            self.add_neighbor(name, neighbor);
            trace!("Node added to context (first pass)");
        }
        
        // Second pass: Resolve via node names to NodeIDs
        for (node_id, via_names) in via_strings {
            trace!("Second pass: Resolving via paths for node {:?}", 
                   base32::encode(base32::Alphabet::RFC4648 { padding: false }, &node_id));
            
            let mut resolved_via = Vec::new();
            for via_name in via_names {
                match self.neighbor_aliases.get(&via_name) {
                    Some(via_node_id) => {
                        resolved_via.push(*via_node_id);
                        trace!("Resolved via node '{}' to {:?}", via_name, 
                               base32::encode(base32::Alphabet::RFC4648 { padding: false }, via_node_id));
                    }
                    None => {
                        // Try to decode as base32 NodeID
                        match base32::decode(base32::Alphabet::RFC4648 { padding: false }, &via_name) {
                            Some(bytes) if bytes.len() == 32 => {
                                let mut via_node_id = [0u8; 32];
                                via_node_id.copy_from_slice(&bytes);
                                resolved_via.push(via_node_id);
                                trace!("Resolved via node '{}' as direct NodeID", via_name);
                            }
                            _ => {
                                return Err(anyhow::anyhow!(
                                    "Unknown via node '{}' for node {:?}", 
                                    via_name,
                                    base32::encode(base32::Alphabet::RFC4648 { padding: false }, &node_id)
                                ));
                            }
                        }
                    }
                }
            }
            
            // Update the node's via field
            if let Some(node) = self.neighbors.get_mut(&node_id) {
                node.via = resolved_via;
                trace!("Updated via paths for node {:?}", 
                       base32::encode(base32::Alphabet::RFC4648 { padding: false }, &node_id));
            }
        }
        
        Ok(())
    }

    /// Parse a remote node without via resolution (for first pass loading)
    pub fn parse_remote_node_without_via(node: &RemoteNodeDiskConfig) -> Result<RemoteNNCPNode, Error> {
        let b32_alph = RFC4648 { padding: false };
        let signpub_b32 = decode(b32_alph, &node.signpub);
        let exchpub_b32 = decode(b32_alph, &node.exchpub);
        let noisepub: Option<Vec<u8>>;
        if signpub_b32.is_none() {
            error!("Failed to base32 decode signing public key for node");
            return Err(anyhow!(NNCPError::Base32DecodeError));
        }
        let signpub_bytes: [u8; 32] = match signpub_b32.unwrap().try_into() {
            Ok(pk) => pk,
            Err(_e) => {
                error!("Incorrect signing key length for node");
                return Err(anyhow!(NNCPError::KeyLengthError { expected_len: 32 }));
            }
        };
        if exchpub_b32.is_none() {
            error!("Failed to base32 decode exchange public key for node");
            return Err(anyhow!(NNCPError::Base32DecodeError));
        }
        let exchpub_bytes: [u8; 32] = match exchpub_b32.unwrap().try_into() {
            Ok(b) => b,
            Err(_e) => {
                error!("Incorrect exchange public key size for node (must be 32 bytes)",);
                return Err(anyhow!(NNCPError::KeyLengthError { expected_len: 32 }));
            }
        };
        match &node.noisepub {
            Some(np_key) => {
                // This remote node has a noise protocol public key; we can do online exchange with it
                let noisepub_b32 = decode(b32_alph, np_key);
                if noisepub_b32.is_none() {
                    error!("Unable to parse noise protocol public key as base32 for node",);
                    return Err(anyhow!(NNCPError::Base32DecodeError));
                }
                let np = noisepub_b32.unwrap();
                if np.len() != 32 {
                    error!("Noise public key for node isn't 32 bytes");
                    return Err(anyhow!(NNCPError::KeyLengthError { expected_len: 32 }));
                }
                noisepub = Some(np);
            }
            None => {
                noisepub = None;
            }
        }
        
        // Process via field: convert node names to NodeIDs
        // Note: This is a simplified implementation that assumes via node names
        // are already resolved. In a full implementation, we'd need to resolve
        // node names to NodeIDs from the neighbor configuration.
        let via: Vec<nncp_rs::nncp::NodeID> = Vec::new(); // TODO: Implement via node name resolution
        
        let neighbor = RemoteNNCPNode::new(signpub_bytes, exchpub_bytes, noisepub, via)?;
        Ok(neighbor)
    }
    
    /// Parse a remote node (backwards compatibility - calls parse_remote_node_without_via)
    /// 
    /// Note: This creates a node with empty via field. For proper via resolution,
    /// use the two-pass loading in set_neighbors().
    pub fn parse_remote_node(node: &RemoteNodeDiskConfig) -> Result<RemoteNNCPNode, Error> {
        Context::parse_remote_node_without_via(node)
    }
}
