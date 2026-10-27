//! Mutual TLS for the signer's API (`[tls]` in `signer.toml`).
//!
//! The signer presents its certificate and accepts only clients whose
//! certificate chains to `client_ca`, so a stolen bearer token alone no longer
//! reaches it. TLS is rustls with the `ring` provider.

use std::net::{SocketAddr, TcpListener};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum_server::Handle;
use axum_server::tls_rustls::RustlsConfig;
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::server::WebPkiClientVerifier;
use rustls::{RootCertStore, ServerConfig};

use crate::config::Tls;

fn certs(path: &std::path::Path) -> Result<Vec<CertificateDer<'static>>, String> {
    let certs = CertificateDer::pem_file_iter(path)
        .and_then(|it| it.collect::<Result<Vec<_>, _>>())
        .map_err(|e| format!("reading certificates from {}: {e}", path.display()))?;
    if certs.is_empty() {
        return Err(format!("{} holds no PEM certificate", path.display()));
    }
    Ok(certs)
}

/// Builds the server configuration: this signer's certificate, and client
/// certificates required and verified against `client_ca`.
pub fn server_config(tls: &Tls) -> Result<Arc<ServerConfig>, String> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let key = PrivateKeyDer::from_pem_file(&tls.key)
        .map_err(|e| format!("reading the private key from {}: {e}", tls.key.display()))?;
    let mut roots = RootCertStore::empty();
    for ca in certs(&tls.client_ca)? {
        roots.add(ca).map_err(|e| format!("{}: {e}", tls.client_ca.display()))?;
    }
    let verifier = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider.clone())
        .build()
        .map_err(|e| format!("client verification: {e}"))?;
    let config = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_client_cert_verifier(verifier)
        .with_single_cert(certs(&tls.cert)?, key)
        .map_err(|e| format!("{}: {e}", tls.cert.display()))?;
    Ok(Arc::new(config))
}

/// Serves `app` over mutual TLS until `handle` is shut down.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    config: Arc<ServerConfig>,
    handle: Handle<SocketAddr>,
) -> Result<(), String> {
    listener.set_nonblocking(true).map_err(|e| e.to_string())?;
    axum_server::from_tcp_rustls(listener, RustlsConfig::from_config(config))
        .map_err(|e| e.to_string())?
        .handle(handle)
        .serve(app.into_make_service())
        .await
        .map_err(|e| e.to_string())
}

/// How long in-flight requests get to finish on shutdown.
pub const SHUTDOWN_GRACE: Duration = Duration::from_secs(10);
