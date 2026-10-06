//! Reading the network's latest ledger from Stellar RPC.

use std::time::Duration;

/// Asks a Stellar RPC server for its latest ledger sequence (`getLatestLedger`).
///
/// Blocking; call it from a blocking thread.
pub fn latest_ledger(url: &str) -> Result<u32, String> {
    let agent: ureq::Agent = ureq::Agent::config_builder().timeout_global(Some(Duration::from_secs(10))).build().into();
    let body = serde_json::json!({ "jsonrpc": "2.0", "id": 1, "method": "getLatestLedger" }).to_string();
    let mut resp = agent
        .post(url)
        .header("content-type", "application/json")
        .send(body.as_str())
        .map_err(|e| format!("getLatestLedger: {e}"))?;
    let text = resp.body_mut().read_to_string().map_err(|e| format!("getLatestLedger: {e}"))?;
    let v: serde_json::Value = serde_json::from_str(&text).map_err(|e| format!("getLatestLedger: {e}"))?;
    if let Some(err) = v.get("error") {
        return Err(format!("getLatestLedger: {err}"));
    }
    v.pointer("/result/sequence")
        .and_then(serde_json::Value::as_u64)
        .and_then(|s| u32::try_from(s).ok())
        .filter(|s| *s > 0)
        .ok_or_else(|| "getLatestLedger: no sequence in the response".into())
}
