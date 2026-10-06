//! `tessera`: key generation, transaction inspection and policy checks.

use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Parser, Subcommand};
use tessera_core::keys::{self, KdfParams, ShareFile};
use tessera_core::stellar::{self, Network};
use tessera_policy::{Intent, OpKind, Policy, format_amount};

#[derive(Parser)]
#[command(name = "tessera", version, about = "Threshold signing for Stellar accounts.")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate key shares with a trusted dealer and write them encrypted.
    ///
    /// Each share is encrypted with `$TESSERA_PASSPHRASE_<n>` if set, otherwise
    /// `$TESSERA_PASSPHRASE`. The dealer sees the whole key while it runs: use an
    /// offline machine for anything that will hold real funds.
    Keygen {
        /// Signatures required.
        #[arg(long)]
        threshold: u16,
        /// Participants.
        #[arg(long)]
        signers: u16,
        /// Directory to write share-1.json … share-N.json into.
        #[arg(long)]
        out: PathBuf,
        /// Cheap KDF settings for tests and demos. Never for real keys.
        #[arg(long, hide = true)]
        insecure_fast_kdf: bool,
    },
    /// Decode a transaction envelope (base64 XDR, or `-` for stdin) and show what it does.
    Inspect {
        /// Envelope, or `-`.
        envelope: String,
        /// Network used for the hash.
        #[arg(long, default_value = "public")]
        network: String,
    },
    /// Judge a transaction against a policy, as a signer would. Exit status 1 if refused.
    Check {
        /// Policy file.
        #[arg(long)]
        policy: PathBuf,
        /// Group account (`G…`).
        #[arg(long)]
        account: String,
        /// Envelope, or `-`.
        envelope: String,
    },
    /// Show the public header of a share file.
    Share {
        /// Share file.
        file: PathBuf,
    },
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode, String> {
    match cli.command {
        Command::Keygen { threshold, signers, out, insecure_fast_kdf } => {
            let kdf =
                if insecure_fast_kdf { KdfParams { m_cost: 64, t_cost: 1, p_cost: 1 } } else { KdfParams::default() };
            keygen(threshold, signers, &out, kdf)
        }
        Command::Inspect { envelope, network } => inspect(&read_envelope(&envelope)?, &Network::from_name(&network)),
        Command::Check { policy, account, envelope } => check(&policy, &account, &read_envelope(&envelope)?),
        Command::Share { file } => {
            let f = ShareFile::from_json(&read(&file)?).map_err(|e| e.to_string())?;
            let h = &f.header;
            println!(
                "account     {}\nidentifier  {}\nthreshold   {} of {}",
                h.account, h.identifier, h.threshold, h.signers
            );
            Ok(ExitCode::SUCCESS)
        }
    }
}

fn read(path: &Path) -> Result<String, String> {
    std::fs::read_to_string(path).map_err(|e| format!("reading {}: {e}", path.display()))
}

fn read_envelope(arg: &str) -> Result<String, String> {
    if arg != "-" {
        return Ok(arg.to_owned());
    }
    let mut s = String::new();
    std::io::stdin().read_to_string(&mut s).map_err(|e| format!("reading stdin: {e}"))?;
    Ok(s)
}

fn keygen(threshold: u16, signers: u16, out: &Path, kdf: KdfParams) -> Result<ExitCode, String> {
    let fallback = std::env::var("TESSERA_PASSPHRASE").ok();
    let passphrases = (1..=signers)
        .map(|i| {
            std::env::var(format!("TESSERA_PASSPHRASE_{i}"))
                .ok()
                .or_else(|| fallback.clone())
                .filter(|p| !p.is_empty())
                .ok_or_else(|| format!("set TESSERA_PASSPHRASE_{i} or TESSERA_PASSPHRASE"))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let shares = keys::deal(threshold, signers).map_err(|e| e.to_string())?;
    std::fs::create_dir_all(out).map_err(|e| format!("creating {}: {e}", out.display()))?;
    for (i, (share, pass)) in shares.iter().zip(&passphrases).enumerate() {
        let file = share.seal(pass.as_bytes(), kdf).map_err(|e| e.to_string())?;
        let path = out.join(format!("share-{}.json", i.saturating_add(1)));
        if path.exists() {
            return Err(format!("{} already exists; refusing to overwrite a key share", path.display()));
        }
        std::fs::write(&path, file.to_json().map_err(|e| e.to_string())? + "\n")
            .map_err(|e| format!("writing {}: {e}", path.display()))?;
    }
    let account = shares.first().map(|s| s.account()).unwrap_or_default();
    println!("{account}");
    eprintln!("wrote {signers} shares to {}; any {threshold} can sign for {account}", out.display());
    Ok(ExitCode::SUCCESS)
}

fn describe(intent: &Intent) -> String {
    let mut out = format!(
        "source      {}\nfee         {} stroops{}\n",
        intent.source,
        intent.fee,
        if intent.fee_bump { " (fee bump)" } else { "" }
    );
    out.push_str(&match intent.max_time {
        Some(t) => format!("expires     {t} (unix)\n"),
        None => "expires     never\n".to_owned(),
    });
    for (i, op) in intent.operations.iter().enumerate() {
        let what = match &op.kind {
            OpKind::Payment { destination, asset, amount } => {
                format!("pay {} {asset} to {destination}", format_amount(i128::from(*amount)))
            }
            OpKind::CreateAccount { destination, starting_balance } => {
                format!("create {destination} with {} native", format_amount(i128::from(*starting_balance)))
            }
            OpKind::InvokeContract { contract, function } => format!("call {contract}.{function}()"),
            OpKind::Other(name) => name.clone(),
        };
        let on_behalf = op.source.as_ref().map(|s| format!("  [as {s}]")).unwrap_or_default();
        out.push_str(&format!("op {i:<8} {what}{on_behalf}\n"));
    }
    out
}

fn inspect(b64: &str, network: &Network) -> Result<ExitCode, String> {
    let env = stellar::decode_envelope(b64).map_err(|e| e.to_string())?;
    let hash = stellar::transaction_hash(network, &env).map_err(|e| e.to_string())?;
    print!("hash        {}\n{}", hex::encode(hash), describe(&Intent::from_envelope(&env)));
    Ok(ExitCode::SUCCESS)
}

fn check(policy: &Path, account: &str, b64: &str) -> Result<ExitCode, String> {
    let policy = Policy::from_toml(&read(policy)?).map_err(|e| e.to_string())?;
    let env = stellar::decode_envelope(b64).map_err(|e| e.to_string())?;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
    let decision = policy.evaluate(&Intent::from_envelope(&env), account, now, |_| 0);
    if decision.approved() {
        println!("APPROVED");
        return Ok(ExitCode::SUCCESS);
    }
    println!("REFUSED");
    for v in &decision.violations {
        println!("  - {v}");
    }
    Ok(ExitCode::from(1))
}
