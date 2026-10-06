//! Signer configuration file.

use std::path::{Path, PathBuf};

use serde::Deserialize;

/// `signer.toml`. Relative paths resolve against the config file's directory.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    /// Address to listen on, e.g. `127.0.0.1:7401`.
    pub listen: String,
    /// `public`, `testnet` or a network passphrase.
    pub network: String,
    /// Encrypted key share produced by `tessera keygen`.
    pub share: PathBuf,
    /// Policy file.
    pub policy: PathBuf,
    /// Where the spend ledger lives.
    pub state_dir: PathBuf,
    /// Environment variable holding the bearer token the coordinator must send.
    /// Leave unset only for local experiments.
    #[serde(default)]
    pub token_env: Option<String>,
    /// Stellar RPC this signer reads the latest ledger from when signing
    /// authorization entries. Without it, the coordinator's value is trusted
    /// within limits.
    #[serde(default)]
    pub rpc: Option<String>,
}

impl Config {
    /// Loads a config file and resolves its relative paths.
    pub fn load(path: &Path) -> Result<Self, String> {
        let text = std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))?;
        let mut c: Config = toml::from_str(&text).map_err(|e| format!("{}: {e}", path.display()))?;
        let base = path.parent().unwrap_or(Path::new("."));
        for p in [&mut c.share, &mut c.policy, &mut c.state_dir] {
            if p.is_relative() {
                *p = base.join(&*p);
            }
        }
        Ok(c)
    }
}
