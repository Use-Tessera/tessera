use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use sha2::{Digest, Sha256};
use tessera_core::keys::KeyShare;
use tessera_core::protocol::{
    AggregateRequest, AggregateResponse, ErrorBody, Info, PROTOCOL, Round1Request, Round1Response, Round2Request,
    Round2Response,
};
use tessera_core::stellar::{self, Network};
use tessera_core::{Error, signing};
use tessera_policy::{Intent, Policy};

use crate::state::{NonceError, Nonces, SpendLedger};

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
}

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
        })
    }

    /// Replaces the wall clock (tests).
    pub fn with_clock(mut self, clock: impl Fn() -> u64 + Send + Sync + 'static) -> Self {
        self.clock = Box::new(clock);
        self
    }
}

/// The signer's HTTP routes.
pub fn router(signer: Arc<Signer>) -> Router {
    Router::new()
        .route("/v1/info", get(info))
        .route("/v1/round1", post(round1))
        .route("/v1/round2", post(round2))
        .route("/v1/aggregate", post(aggregate))
        .route_layer(middleware::from_fn_with_state(signer.clone(), authorize))
        .with_state(signer)
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
