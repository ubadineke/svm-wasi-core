//! A blocking, native (non-wasm) HTTP RPC transport — for tooling and
//! scripts that run on the host rather than inside a wasm32-wasip2
//! component, where [`super::waki_transport::WakiTransport`]
//! (`wasi:http`-only) doesn't compile. Never used by a plugin itself; a
//! plugin always talks to `wasi:http` via `waki`.

use super::{RpcError, RpcTransport};
use serde_json::Value;

pub struct NativeHttpTransport {
    url: String,
}

impl NativeHttpTransport {
    pub fn new(url: impl Into<String>) -> Self {
        Self { url: url.into() }
    }
}

impl RpcTransport for NativeHttpTransport {
    fn send(&self, request: Value) -> Result<Value, RpcError> {
        ureq::post(&self.url)
            .send_json(&request)
            .map_err(|e| RpcError::Transport(e.to_string()))?
            .body_mut()
            .read_json::<Value>()
            .map_err(|e| RpcError::Transport(format!("invalid JSON response: {e}")))
    }
}
