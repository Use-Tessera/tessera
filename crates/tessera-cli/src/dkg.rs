//! `tessera dkg`: run distributed key generation from the command line.
//!
//! Each participant runs the steps on their own machine and exchanges the
//! files they print through any channel, such as a shared folder or chat:
//!
//! ```text
//! tessera dkg start --index 1 --threshold 2 --signers 3 --state p1.state > round1-1.json
//! tessera dkg fingerprint round1-*.json            # compare with everyone, by voice
//! tessera dkg exchange --state p1.state --fingerprint <hex> --out round2/ round1-*.json
//! tessera dkg finish --state p1.state --out share.json round2/*.json
//! ```

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Subcommand;
use tessera_core::dkg::{self, Round1Message, Round2Message, State, StateFile};
use tessera_core::keys::KdfParams;

use crate::{passphrase, read, write_new};

#[derive(Subcommand)]
pub enum Step {
    /// Step 1: create this participant's secret state and print its round-1 message.
    Start {
        /// This participant's position, 1 to `--signers`. Every participant needs a different one.
        #[arg(long)]
        index: u16,
        /// Signatures required.
        #[arg(long)]
        threshold: u16,
        /// Participants.
        #[arg(long)]
        signers: u16,
        /// Where to keep the encrypted state between steps.
        #[arg(long)]
        state: PathBuf,
        /// Cheap KDF settings for tests and demos. Never for real keys.
        #[arg(long, hide = true)]
        insecure_fast_kdf: bool,
    },
    /// Print the fingerprint of a set of round-1 messages, for comparing out of band.
    Fingerprint {
        /// Every participant's round-1 message.
        #[arg(required = true)]
        round1: Vec<PathBuf>,
    },
    /// Step 2: check the round-1 set and write one encrypted round-2 file per other participant.
    Exchange {
        /// State from `dkg start`.
        #[arg(long)]
        state: PathBuf,
        /// The fingerprint every participant agreed on.
        #[arg(long)]
        fingerprint: String,
        /// Directory for the round-2 files.
        #[arg(long)]
        out: PathBuf,
        /// Every participant's round-1 message.
        #[arg(required = true)]
        round1: Vec<PathBuf>,
    },
    /// Step 3: derive this participant's key share from the round-2 files addressed to it.
    Finish {
        /// State from `dkg exchange`. Deleted once the share is written.
        #[arg(long)]
        state: PathBuf,
        /// Where to write the encrypted key share.
        #[arg(long)]
        out: PathBuf,
        /// Round-2 files; those addressed to other participants are ignored.
        #[arg(required = true)]
        round2: Vec<PathBuf>,
    },
}

pub fn run(step: Step) -> Result<ExitCode, String> {
    match step {
        Step::Start { index, threshold, signers, state, insecure_fast_kdf } => {
            let kdf =
                if insecure_fast_kdf { KdfParams { m_cost: 64, t_cost: 1, p_cost: 1 } } else { KdfParams::default() };
            let pass = passphrase()?;
            let (s, message) = dkg::start(index, threshold, signers).map_err(|e| e.to_string())?;
            let file = s.seal(pass.as_bytes(), kdf).map_err(|e| e.to_string())?;
            write_new(&state, &file.to_json().map_err(|e| e.to_string())?)?;
            println!("{}", json(&message)?);
            eprintln!("participant {index} of {signers}: send this round-1 message to every other participant");
            Ok(ExitCode::SUCCESS)
        }
        Step::Fingerprint { round1 } => {
            let messages: Vec<Round1Message> = load_all(&round1)?;
            println!("{}", dkg::fingerprint(&messages).map_err(|e| e.to_string())?);
            Ok(ExitCode::SUCCESS)
        }
        Step::Exchange { state, fingerprint, out, round1 } => {
            let pass = passphrase()?;
            let file = StateFile::from_json(&read(&state)?).map_err(|e| e.to_string())?;
            let State::Round1(s) = file.open(pass.as_bytes()).map_err(|e| e.to_string())? else {
                return Err(format!("{} has already run exchange; run finish next", state.display()));
            };
            let mut messages: Vec<Round1Message> = load_all(&round1)?;
            if !messages.iter().any(|m| m.identifier == s.message().identifier) {
                messages.push(s.message().clone());
            }
            let actual = dkg::fingerprint(&messages).map_err(|e| e.to_string())?;
            if !actual.eq_ignore_ascii_case(fingerprint.trim()) {
                return Err(format!(
                    "round-1 fingerprint is {actual}, not the agreed {fingerprint}: a message was changed or is missing"
                ));
            }
            let (next, outgoing) = dkg::exchange(s, &messages).map_err(|e| e.to_string())?;
            std::fs::create_dir_all(&out).map_err(|e| format!("creating {}: {e}", out.display()))?;
            for m in &outgoing {
                let path = out.join(format!("round2-{}-to-{}.json", short(&m.from), short(&m.to)));
                write_new(&path, &json(m)?)?;
            }
            let sealed = next.seal(pass.as_bytes(), file.secret.kdf).map_err(|e| e.to_string())?;
            replace(&state, &sealed.to_json().map_err(|e| e.to_string())?)?;
            eprintln!("wrote {} round-2 files to {}; deliver each to its recipient", outgoing.len(), out.display());
            Ok(ExitCode::SUCCESS)
        }
        Step::Finish { state, out, round2 } => {
            let pass = passphrase()?;
            let file = StateFile::from_json(&read(&state)?).map_err(|e| e.to_string())?;
            let State::Round2(s) = file.open(pass.as_bytes()).map_err(|e| e.to_string())? else {
                return Err(format!("{} has not run exchange yet", state.display()));
            };
            let messages: Vec<Round2Message> = load_all(&round2)?;
            let share = dkg::finish(s, &messages).map_err(|e| e.to_string())?;
            let sealed = share.seal(pass.as_bytes(), file.secret.kdf).map_err(|e| e.to_string())?;
            write_new(&out, &(sealed.to_json().map_err(|e| e.to_string())? + "\n"))?;
            std::fs::remove_file(&state).map_err(|e| format!("removing {}: {e}", state.display()))?;
            println!("{}", share.account());
            eprintln!(
                "wrote {}; any {} of {} participants can sign for {}",
                out.display(),
                share.threshold(),
                share.signers(),
                share.account()
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn load_all<T: serde::de::DeserializeOwned>(paths: &[PathBuf]) -> Result<Vec<T>, String> {
    paths.iter().map(|p| serde_json::from_str(&read(p)?).map_err(|e| format!("{}: {e}", p.display()))).collect()
}

fn json(v: &impl serde::Serialize) -> Result<String, String> {
    serde_json::to_string_pretty(v).map_err(|e| e.to_string())
}

/// Replaces a file by writing a sibling and renaming it over the original.
fn replace(path: &Path, contents: &str) -> Result<(), String> {
    let tmp = path.with_extension("tmp");
    std::fs::write(&tmp, contents).map_err(|e| format!("writing {}: {e}", tmp.display()))?;
    std::fs::rename(&tmp, path).map_err(|e| format!("replacing {}: {e}", path.display()))
}

fn short(id: &str) -> &str {
    id.get(..8).unwrap_or(id)
}
