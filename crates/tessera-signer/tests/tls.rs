//! Mutual TLS: the signer serves only clients holding a certificate from its CA.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::indexing_slicing)]

use std::sync::Arc;

use rcgen::{BasicConstraints, Certificate, CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore};
use tessera_core::keys;
use tessera_core::stellar::Network;
use tessera_signer::config::Tls;
use tessera_signer::state::SpendLedger;
use tessera_signer::{Signer, router, tls};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const POLICY: &str = include_str!("../../../examples/policy.toml");

struct Ca {
    cert: Certificate,
    key: KeyPair,
}

fn ca() -> Ca {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    Ca { cert: params.self_signed(&key).unwrap(), key }
}

fn issue(ca: &Ca, name: &str, usage: ExtendedKeyUsagePurpose) -> (Certificate, KeyPair) {
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(vec![name.to_owned()]).unwrap();
    params.extended_key_usages = vec![usage];
    (params.signed_by(&key, &ca.cert, &ca.key).unwrap(), key)
}

/// Starts the real signer router over mutual TLS; returns its port.
async fn serve(dir: &std::path::Path, ca: &Ca) -> (u16, axum_server::Handle<std::net::SocketAddr>) {
    let (cert, key) = issue(ca, "localhost", ExtendedKeyUsagePurpose::ServerAuth);
    let write = |name: &str, pem: String| {
        let p = dir.join(name);
        std::fs::write(&p, pem).unwrap();
        p
    };
    let files = Tls {
        cert: write("signer.crt", cert.pem()),
        key: write("signer.key", key.serialize_pem()),
        client_ca: write("ca.crt", ca.cert.pem()),
    };
    let share = keys::deal(2, 3).unwrap().remove(0);
    let ledger = SpendLedger::open(&dir.join("spend.jsonl")).unwrap();
    let signer = Signer::new(share, Network::from_name("testnet"), POLICY, Some("token".into()), ledger).unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = axum_server::Handle::new();
    let config = tls::server_config(&files).unwrap();
    tokio::spawn(tls::serve(listener, router(Arc::new(signer)), config, handle.clone()));
    handle.listening().await;
    (port, handle)
}

/// GET /healthz over TLS, trusting `ca` for the server and presenting `client`.
async fn healthz(port: u16, ca: &Ca, client: Option<(&Certificate, &KeyPair)>) -> Result<String, String> {
    let mut roots = RootCertStore::empty();
    roots.add(ca.cert.der().clone()).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
    let config = match client {
        Some((cert, key)) => builder
            .with_client_auth_cert(
                vec![CertificateDer::from(cert.der().to_vec())],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
            )
            .unwrap(),
        None => builder.with_no_client_auth(),
    };
    let tcp = tokio::net::TcpStream::connect(("127.0.0.1", port)).await.map_err(|e| e.to_string())?;
    let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
    let mut stream = connector
        .connect(ServerName::try_from("localhost").unwrap(), tcp)
        .await
        .map_err(|e| format!("handshake: {e}"))?;
    stream
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await
        .map_err(|e| format!("write: {e}"))?;
    let mut out = String::new();
    stream.read_to_string(&mut out).await.map_err(|e| format!("read: {e}"))?;
    Ok(out)
}

#[tokio::test]
async fn serves_clients_with_a_certificate_from_its_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca = ca();
    let (port, handle) = serve(dir.path(), &ca).await;
    let (cert, key) = issue(&ca, "coordinator", ExtendedKeyUsagePurpose::ClientAuth);
    let reply = healthz(port, &ca, Some((&cert, &key))).await.unwrap();
    assert!(reply.starts_with("HTTP/1.1 200"), "{reply}");
    handle.shutdown();
}

#[tokio::test]
async fn refuses_clients_without_a_certificate() {
    let dir = tempfile::tempdir().unwrap();
    let ca = ca();
    let (port, handle) = serve(dir.path(), &ca).await;
    let outcome = healthz(port, &ca, None).await;
    assert!(!outcome.as_deref().is_ok_and(|r| r.contains("200")), "served without a client certificate: {outcome:?}");
    handle.shutdown();
}

#[tokio::test]
async fn refuses_certificates_from_another_ca() {
    let dir = tempfile::tempdir().unwrap();
    let ca = ca();
    let (port, handle) = serve(dir.path(), &ca).await;
    let stranger = self::ca();
    let (cert, key) = issue(&stranger, "coordinator", ExtendedKeyUsagePurpose::ClientAuth);
    let outcome = healthz(port, &ca, Some((&cert, &key))).await;
    assert!(!outcome.as_deref().is_ok_and(|r| r.contains("200")), "served a certificate from another CA: {outcome:?}");
    handle.shutdown();
}

#[test]
fn a_missing_or_empty_file_is_a_clear_error() {
    let dir = tempfile::tempdir().unwrap();
    let empty = dir.path().join("empty.pem");
    std::fs::write(&empty, "").unwrap();
    let files = Tls { cert: empty.clone(), key: dir.path().join("missing.key"), client_ca: empty };
    let err = tls::server_config(&files).unwrap_err();
    assert!(err.contains("missing.key"), "{err}");
}
