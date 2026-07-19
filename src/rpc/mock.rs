//! A canned-response transport for host tests: no network, ever. Replays
//! queued JSON-RPC response envelopes in call order and records every
//! request it received, so a test can assert both "what came back" and
//! "what we actually sent" (method, params, id).

use super::{RpcError, RpcTransport};
use serde_json::{json, Value};
use std::sync::Mutex;

pub struct MockTransport {
    responses: Mutex<Vec<Value>>,
    received: Mutex<Vec<Value>>,
}

impl MockTransport {
    /// Queues raw JSON-RPC response envelopes (`{"result": ...}` or
    /// `{"error": {...}}`) to replay in order.
    pub fn new(responses: Vec<Value>) -> Self {
        // Stored reversed so `pop` (from the end, O(1)) replays in the
        // original front-to-back order without shifting the whole Vec.
        let mut responses = responses;
        responses.reverse();
        Self {
            responses: Mutex::new(responses),
            received: Mutex::new(Vec::new()),
        }
    }

    /// Convenience: queues successful responses, wrapping each `result`
    /// value in the envelope automatically.
    pub fn ok(results: Vec<Value>) -> Self {
        Self::new(results.into_iter().map(|r| json!({"result": r})).collect())
    }

    /// Every request this transport has received so far, in call order.
    pub fn received(&self) -> Vec<Value> {
        self.received.lock().unwrap().clone()
    }
}

impl RpcTransport for MockTransport {
    fn send(&self, request: Value) -> Result<Value, RpcError> {
        self.received.lock().unwrap().push(request);
        self.responses
            .lock()
            .unwrap()
            .pop()
            .ok_or_else(|| RpcError::Transport("MockTransport: no more queued responses".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replays_responses_in_order() {
        let transport = MockTransport::new(vec![json!({"result": 1}), json!({"result": 2})]);
        assert_eq!(transport.send(json!({})).unwrap(), json!({"result": 1}));
        assert_eq!(transport.send(json!({})).unwrap(), json!({"result": 2}));
    }

    #[test]
    fn errors_once_exhausted_rather_than_panicking() {
        let transport = MockTransport::new(vec![json!({"result": 1})]);
        transport.send(json!({})).unwrap();
        assert!(transport.send(json!({})).is_err());
    }

    #[test]
    fn records_every_request_received() {
        let transport = MockTransport::ok(vec![json!(1), json!(2)]);
        transport.send(json!({"id": 1, "method": "a"})).unwrap();
        transport.send(json!({"id": 2, "method": "b"})).unwrap();

        let received = transport.received();
        assert_eq!(received.len(), 2);
        assert_eq!(received[0]["method"], "a");
        assert_eq!(received[1]["method"], "b");
    }
}
