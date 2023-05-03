//! Context related to a command invocation
use std::path::PathBuf;
use std::path::Path;

/// Related context for a command: config, spool, node keys, oh my!
pub struct Context {
    //config: config::Config,
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
        let project_dir = directories::ProjectDirs::from("rs", "", "nncp")
            .expect("Unable to create project directory");
        let data_path = project_dir.data_local_dir();
        let mut spool_path = PathBuf::from(&data_path);
        spool_path.push("spool");
        let mut log_path = PathBuf::from(data_path);
        log_path.push("nncp.log");
        let ctx = Context {
            config_path,
            log_path,
            spool_path,
        };
        ctx
    }
}

impl Context {
    fn new (config_path: impl AsRef<Path>, log_path: impl AsRef<Path>, spool_path: impl AsRef<Path>) -> Self {
        let config_path: PathBuf = config_path.as_ref().to_path_buf();
        let log_path: PathBuf = log_path.as_ref().to_path_buf();
        let spool_path: PathBuf = spool_path.as_ref().to_path_buf();
        Context {
            config_path,
            log_path,
            spool_path
        }
    }
}