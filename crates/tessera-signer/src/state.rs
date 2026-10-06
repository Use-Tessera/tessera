//! Signer state: single-use nonces and the spend ledger behind daily limits.

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use tessera_core::frost::round1::SigningNonces;

/// How long round-1 nonces wait for round 2.
pub const NONCE_TTL: Duration = Duration::from_secs(120);
/// Most sessions a signer keeps open at once.
pub const MAX_SESSIONS: usize = 1024;

/// Round-1 nonces by session. Each is handed out at most once.
#[derive(Default)]
pub struct Nonces(Mutex<HashMap<String, (SigningNonces, Instant)>>);

/// Why nonces could not be stored.
#[derive(Debug, PartialEq, Eq)]
pub enum NonceError {
    /// A session with this ID already exists.
    Duplicate,
    /// Too many open sessions.
    Full,
}

impl Nonces {
    /// Stores nonces for a new session.
    pub fn insert(&self, session: &str, nonces: SigningNonces) -> Result<(), NonceError> {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.retain(|_, (_, at)| at.elapsed() < NONCE_TTL);
        if map.contains_key(session) {
            return Err(NonceError::Duplicate);
        }
        if map.len() >= MAX_SESSIONS {
            return Err(NonceError::Full);
        }
        map.insert(session.to_owned(), (nonces, Instant::now()));
        Ok(())
    }

    /// Removes and returns a session's nonces. A second call for the same session returns `None`.
    pub fn take(&self, session: &str) -> Option<SigningNonces> {
        let mut map = self.0.lock().unwrap_or_else(|p| p.into_inner());
        map.remove(session).filter(|(_, at)| at.elapsed() < NONCE_TTL).map(|(n, _)| n)
    }
}

#[derive(Serialize, Deserialize)]
struct Entry {
    time: u64,
    tx: String,
    asset: String,
    amount: i128,
}

/// Append-only record of what this signer approved, persisted as JSON lines.
pub struct SpendLedger {
    path: PathBuf,
    entries: Mutex<Vec<Entry>>,
}

const DAY: u64 = 86_400;

impl SpendLedger {
    /// Opens (or creates) the ledger at `path`.
    pub fn open(path: &Path) -> std::io::Result<Self> {
        let mut entries = Vec::new();
        if path.exists() {
            for line in BufReader::new(File::open(path)?).lines() {
                let line = line?;
                if line.trim().is_empty() {
                    continue;
                }
                let e: Entry = serde_json::from_str(&line).map_err(std::io::Error::other)?;
                entries.push(e);
            }
        }
        Ok(Self { path: path.to_owned(), entries: Mutex::new(entries) })
    }

    /// Stroops of `asset` approved in the 24 hours before `now`.
    pub fn spent_since(&self, asset: &str, now: u64) -> i128 {
        let entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        entries
            .iter()
            .filter(|e| e.asset == asset && e.time.saturating_add(DAY) > now)
            .fold(0i128, |acc, e| acc.saturating_add(e.amount))
    }

    /// Durably records approved spend. Called before a signature share leaves the signer.
    pub fn record(&self, now: u64, tx: &str, spend: &[(String, i128)]) -> std::io::Result<()> {
        if spend.is_empty() {
            return Ok(());
        }
        let mut entries = self.entries.lock().unwrap_or_else(|p| p.into_inner());
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        let mut new = Vec::with_capacity(spend.len());
        for (asset, amount) in spend {
            let e = Entry { time: now, tx: tx.to_owned(), asset: asset.clone(), amount: *amount };
            writeln!(file, "{}", serde_json::to_string(&e).map_err(std::io::Error::other)?)?;
            new.push(e);
        }
        file.sync_all()?;
        entries.extend(new);
        Ok(())
    }
}

/// One line of the decision log.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Decision {
    /// Unix seconds.
    pub time: u64,
    /// `transaction` or `authorization`.
    pub kind: String,
    /// Hash that was (or would have been) signed, hex.
    pub hash: String,
    /// Whether a share was released.
    pub approved: bool,
    /// Policy violations when refused.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub violations: Vec<String>,
}

/// Append-only record of every approval and refusal this signer made,
/// independent of the coordinator's audit log.
pub struct DecisionLog {
    path: PathBuf,
    lock: Mutex<()>,
}

impl DecisionLog {
    /// Uses (or creates) the log at `path`.
    pub fn new(path: &Path) -> Self {
        Self { path: path.to_owned(), lock: Mutex::new(()) }
    }

    /// Appends one decision.
    pub fn append(&self, d: &Decision) -> std::io::Result<()> {
        let _guard = self.lock.lock().unwrap_or_else(|p| p.into_inner());
        let mut file = OpenOptions::new().create(true).append(true).open(&self.path)?;
        writeln!(file, "{}", serde_json::to_string(d).map_err(std::io::Error::other)?)
    }

    /// Reads every decision, oldest first.
    pub fn read(&self) -> std::io::Result<Vec<Decision>> {
        if !self.path.exists() {
            return Ok(Vec::new());
        }
        BufReader::new(File::open(&self.path)?)
            .lines()
            .filter(|l| l.as_ref().map_or(true, |l| !l.trim().is_empty()))
            .map(|l| serde_json::from_str(&l?).map_err(std::io::Error::other))
            .collect()
    }
}
