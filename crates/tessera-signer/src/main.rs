//! `tessera-signer`: serve one key share.

use std::path::PathBuf;
use std::sync::Arc;

use clap::Parser;
use tessera_core::keys::ShareFile;
use tessera_core::stellar::Network;
use tessera_signer::config::Config;
use tessera_signer::state::SpendLedger;
use tessera_signer::{Signer, router};

#[derive(Parser)]
#[command(name = "tessera-signer", version, about = "Hold one Tessera key share and co-sign what the policy allows.")]
struct Args {
    /// Signer configuration file.
    #[arg(long, default_value = "signer.toml")]
    config: PathBuf,
    /// Passphrase that decrypts the key share.
    #[arg(long, env = "TESSERA_PASSPHRASE", hide_env_values = true)]
    passphrase: String,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
    tracing_subscriber::fmt().json().with_env_filter(filter).init();
    match run(Args::parse()).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!("{e}");
            std::process::ExitCode::FAILURE
        }
    }
}

async fn run(args: Args) -> Result<(), String> {
    let cfg = Config::load(&args.config)?;
    let read = |p: &PathBuf| std::fs::read_to_string(p).map_err(|e| format!("reading {}: {e}", p.display()));
    let share = ShareFile::from_json(&read(&cfg.share)?)
        .and_then(|f| f.open(args.passphrase.as_bytes()))
        .map_err(|e| e.to_string())?;
    let token = match &cfg.token_env {
        Some(var) => Some(std::env::var(var).map_err(|_| format!("token_env is set but ${var} is empty"))?),
        None => {
            tracing::warn!("no token_env configured: any client that can reach this signer can request signatures");
            None
        }
    };
    std::fs::create_dir_all(&cfg.state_dir).map_err(|e| format!("creating {}: {e}", cfg.state_dir.display()))?;
    let ledger = SpendLedger::open(&cfg.state_dir.join("spend.jsonl")).map_err(|e| format!("opening ledger: {e}"))?;
    let signer = Signer::new(share, Network::from_name(&cfg.network), &read(&cfg.policy)?, token, ledger)?;

    let listener =
        tokio::net::TcpListener::bind(&cfg.listen).await.map_err(|e| format!("binding {}: {e}", cfg.listen))?;
    tracing::info!(listen = cfg.listen, "serving");
    axum::serve(listener, router(Arc::new(signer)))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|e| e.to_string())
}
