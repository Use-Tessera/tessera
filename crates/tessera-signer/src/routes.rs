use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{DefaultBodyLimit, Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use sha2::{Digest, Sha256};
use tessera_core::keys::KeyShare;
use tessera_core::protocol::{
    AggregateRequest, AggregateResponse, AuthAggregateRequest, AuthAggregateResponse, AuthRound2Request, ErrorBody,
    Info, PROTOCOL, Round1Request, Round1Response, Round2Request, Round2Response,
};
use tessera_core::stellar::{self, Network};
use tessera_core::{Error, auth, signing};
use tessera_policy::{AuthIntent, Intent, Policy};

use crate::state::{Decision, DecisionLog, NonceError, Nonces, SpendLedger};

/// Everything a running signer needs.
pub struct Signer {
    share: KeyShare,
    network: Network,
    policy: Policy,
    policy_sha256: String,
    token: Option<String>,
    nonces: Nonces,
    ledger: SpendLedger,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
    highest_ledger: AtomicU32,
    decisions: Option<DecisionLog>,
}

/// How far behind the highest ledger seen a request's `latest_ledger` may be (about a day).
const STALE_LEDGERS: u32 = 17_280;

impl Signer {
    /// Assembles a signer. `policy_text` is hashed so operators can confirm which policy is live.
    pub fn new(
        share: KeyShare,
        network: Network,
        policy_text: &str,
        token: Option<String>,
        ledger: SpendLedger,
    ) -> Result<Self, String> {
        let policy = Policy::from_toml(policy_text).map_err(|e| e.to_string())?;
        if Network::from_name(policy.network()) != network {
            return Err(format!(
                "policy is for network {:?}, signer is configured for {:?}",
                policy.network(),
                network.passphrase()
            ));
        }
        Ok(Self {
            share,
            network,
            policy,
            policy_sha256: hex::encode(Sha256::digest(policy_text.as_bytes())),
            token,
            nonces: Nonces::default(),
            ledger,
            clock: Box::new(|| SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)),
            highest_ledger: AtomicU32::new(0),
            decisions: None,
        })
    }

    /// Records every approval and refusal to `log`.
    pub fn with_decision_log(mut self, log: DecisionLog) -> Self {
        self.decisions = Some(log);
        self
    }

    fn decide(&self, kind: &str, hash: &[u8; 32], violations: &[String]) {
        let Some(log) = &self.decisions else { return };
        let d = Decision {
            time: (self.clock)(),
            kind: kind.into(),
            hash: hex::encode(hash),
            approved: violations.is_empty(),
            violations: violations.to_vec(),
        };
        if let Err(e) = log.append(&d) {
            tracing::error!("writing decision log: {e}");
        }
    }

    /// Replaces the wall clock (tests).
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }
}

/// Largest request body accepted (transaction envelopes are far smaller).
pub const MAX_BODY: usize = 256 * 1024;
/// Longest a request may take.
pub const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// The signer's HTTP routes.
pub fn router(signer: Arc<Signer>) -> Router {
    let api = Router::new()
        .route("/v1/info", get(info))
        .route("/v1/round1", post(round1))
        .route("/v1/round2", post(round2))
        .route("/v1/aggregate", post(aggregate))
        .route("/v1/round2/auth", post(round2_auth))
        .route("/v1/aggregate/auth", post(aggregate_auth))
        .route_layer(middleware::from_fn_with_state(signer.clone(), authorize))
        .with_state(signer);
    Router::new()
        .route("/healthz", get(|| async { Json(serde_json::json!({ "status": "ok" })) }))
        .merge(api)
        .layer(middleware::from_fn(timeout))
        .layer(DefaultBodyLimit::max(MAX_BODY))
}

async fn timeout(req: Request, next: Next) -> Response {
    match tokio::time::timeout(REQUEST_TIMEOUT, next.run(req)).await {
        Ok(resp) => resp,
        Err(_) => ApiError::new(StatusCode::REQUEST_TIMEOUT, "request timed out").into_response(),
    }
}

struct ApiError(StatusCode, ErrorBody);

impl ApiError {
    fn new(status: StatusCode, msg: impl ToString) -> Self {
        Self(status, ErrorBody { error: msg.to_string(), violations: Vec::new() })
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(self.1)).into_response()
    }
}

impl From<Error> for ApiError {
    fn from(e: Error) -> Self {
        match e {
            Error::Malformed { .. } | Error::Frost(_) => Self::new(StatusCode::BAD_REQUEST, e),
            _ => Self::new(StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    }
}

type ApiResult<T> = Result<Json<T>, ApiError>;

async fn authorize(State(s): State<Arc<Signer>>, req: Request, next: Next) -> Response {
    if let Some(token) = &s.token {
        let given =
            req.headers().get("authorization").and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer "));
        let ok = given.is_some_and(|g| constant_time_eq(g.as_bytes(), token.as_bytes()));
        if !ok {
            return ApiError::new(StatusCode::UNAUTHORIZED, "missing or wrong bearer token").into_response();
        }
    }
    next.run(req).await
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn valid_session(id: &str) -> bool {
    (1..=64).contains(&id.len()) && id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

async fn info(State(s): State<Arc<Signer>>) -> Json<Info> {
    Json(Info {
        protocol: PROTOCOL.into(),
        identifier: s.share.identifier_hex(),
        account: s.share.account(),
        threshold: s.share.threshold(),
        signers: s.share.signers(),
        network: s.network.passphrase().into(),
        policy_sha256: s.policy_sha256.clone(),
    })
}

async fn round1(State(s): State<Arc<Signer>>, Json(req): Json<Round1Request>) -> ApiResult<Round1Response> {
    if !valid_session(&req.session) {
        return Err(ApiError::new(StatusCode::BAD_REQUEST, "session must be 1-64 characters of [A-Za-z0-9_-]"));
    }
    let (nonces, commitments) = signing::commit(&s.share);
    s.nonces.insert(&req.session, nonces).map_err(|e| match e {
        NonceError::Duplicate => ApiError::new(StatusCode::CONFLICT, "session already exists"),
        NonceError::Full => ApiError::new(StatusCode::SERVICE_UNAVAILABLE, "too many open sessions"),
    })?;
    Ok(Json(Round1Response {
        identifier: s.share.identifier_hex(),
        commitments: signing::encode_commitments(&commitments)?,
    }))
}

async fn round2(State(s): State<Arc<Signer>>, Json(req): Json<Round2Request>) -> ApiResult<Round2Response> {
    // Nonces are spent the moment round 2 is attempted, whatever the outcome.
    let nonces = s
        .nonces
        .take(&req.session)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "unknown or expired session"))?;
    let envelope = stellar::decode_envelope(&req.envelope)?;
    let now = (s.clock)();

    let intent = Intent::from_envelope(&envelope);
    let decision = s.policy.evaluate(&intent, &s.share.account(), now, |asset| s.ledger.spent_since(asset, now));
    let (package, hash) = signing::signing_package(&s.network, &envelope, &req.commitments)?;
    let tx = hex::encode(hash);
    s.decide("transaction", &hash, &decision.violations);
    if !decision.approved() {
        tracing::warn!(tx, violations = ?decision.violations, "refused");
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            ErrorBody { error: "policy refused the transaction".into(), violations: decision.violations },
        ));
    }

    let share = signing::sign(&s.share, nonces, &package)?;
    let spend: Vec<(String, i128)> = decision.spend.into_iter().collect();
    s.ledger
        .record(now, &tx, &spend)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("recording spend: {e}")))?;
    tracing::info!(tx, "signed");
    Ok(Json(Round2Response { identifier: s.share.identifier_hex(), share }))
}

async fn aggregate(State(s): State<Arc<Signer>>, Json(req): Json<AggregateRequest>) -> ApiResult<AggregateResponse> {
    let mut envelope = stellar::decode_envelope(&req.envelope)?;
    let (package, hash) = signing::signing_package(&s.network, &envelope, &req.commitments)?;
    let signature = signing::aggregate(s.share.public_key_package(), &package, &req.shares)?;
    stellar::attach_signature(&mut envelope, &s.share.group_public_key(), &signature)?;
    Ok(Json(AggregateResponse {
        hash: hex::encode(hash),
        signature: hex::encode(signature),
        envelope: stellar::encode_envelope(&envelope)?,
    }))
}

/// Signs a share over a Soroban authorization entry if the policy allows it.
///
/// The coordinator supplies the network's latest ledger. A signer cannot check
/// it on its own, so it only accepts values that never fall more than about a
/// day behind the highest it has seen; see docs/security-model.md.
async fn round2_auth(State(s): State<Arc<Signer>>, Json(req): Json<AuthRound2Request>) -> ApiResult<Round2Response> {
    let nonces = s
        .nonces
        .take(&req.session)
        .ok_or_else(|| ApiError::new(StatusCode::NOT_FOUND, "unknown or expired session"))?;
    let entry = auth::decode_entry(&req.auth_entry)?;
    let seen = s.highest_ledger.fetch_max(req.latest_ledger, Ordering::SeqCst);
    if req.latest_ledger.saturating_add(STALE_LEDGERS) < seen {
        return Err(ApiError::new(
            StatusCode::BAD_REQUEST,
            format!("latest_ledger {} is stale (seen {seen})", req.latest_ledger),
        ));
    }
    let intent = AuthIntent::from_entry(&entry)
        .ok_or_else(|| ApiError::new(StatusCode::BAD_REQUEST, "only address-credential entries can be signed"))?;
    let now = (s.clock)();
    let decision = s
        .policy
        .evaluate_auth(&intent, &s.share.account(), req.latest_ledger, |asset| s.ledger.spent_since(asset, now));
    let hash = auth::payload_hash(&s.network, &entry)?;
    let tag = hex::encode(hash);
    s.decide("authorization", &hash, &decision.violations);
    if !decision.approved() {
        tracing::warn!(auth = tag, violations = ?decision.violations, "refused");
        return Err(ApiError(
            StatusCode::FORBIDDEN,
            ErrorBody { error: "policy refused the authorization".into(), violations: decision.violations },
        ));
    }
    let package = signing::package_for(&hash, &req.commitments)?;
    let share = signing::sign(&s.share, nonces, &package)?;
    let spend: Vec<(String, i128)> = decision.spend.into_iter().collect();
    s.ledger
        .record(now, &tag, &spend)
        .map_err(|e| ApiError::new(StatusCode::INTERNAL_SERVER_ERROR, format!("recording spend: {e}")))?;
    tracing::info!(auth = tag, "signed");
    Ok(Json(Round2Response { identifier: s.share.identifier_hex(), share }))
}

async fn aggregate_auth(
    State(s): State<Arc<Signer>>,
    Json(req): Json<AuthAggregateRequest>,
) -> ApiResult<AuthAggregateResponse> {
    let mut entry = auth::decode_entry(&req.auth_entry)?;
    let hash = auth::payload_hash(&s.network, &entry)?;
    let package = signing::package_for(&hash, &req.commitments)?;
    let signature = signing::aggregate(s.share.public_key_package(), &package, &req.shares)?;
    auth::attach_signature(&mut entry, &s.share.group_public_key(), &signature)?;
    Ok(Json(AuthAggregateResponse {
        hash: hex::encode(hash),
        signature: hex::encode(signature),
        auth_entry: auth::encode_entry(&entry)?,
    }))
}
