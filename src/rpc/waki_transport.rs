//! `wasi:http` JSON-RPC transport, via `waki`'s blocking client — the only
//! outbound network path available inside a wasm32-wasip2 component (no
//! raw sockets; TLS is terminated host-side). Compiled only for the wasm
//! target (`cfg(target_family = "wasm")` in `Cargo.toml`), so `cargo test`
//! never links it — every RPC test in this crate runs against
//! [`super::mock::MockTransport`] instead.

use super::{RpcError, RpcTransport};
use serde_json::Value;

/// Talks to a single Solana JSON-RPC endpoint over `wasi:http`.
///
/// The endpoint URL is the caller's responsibility to supply — per the
/// bounty's own guidance, a plugin should read it from its `config_read`
/// section (`__config`), supporting a user-supplied RPC URL, and never
/// hardcode an endpoint with an API key baked into the crate.
pub struct WakiTransport {
    url: String,
}

impl WakiTransport {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

impl RpcTransport for WakiTransport {
    fn send(&self, request: Value) -> Result<Value, RpcError> {
        let response = waki::Client::new()
            .post(&self.url)
            .json(&request)
            .send()
            .map_err(|e| RpcError::Transport(e.to_string()))?;

        let status = response.status_code();
        if !(200..300).contains(&status) {
            return Err(RpcError::Transport(format!(
                "HTTP {status} from RPC endpoint"
            )));
        }

        response
            .json::<Value>()
            .map_err(|e| RpcError::Transport(format!("invalid JSON response: {e}")))
    }
}
