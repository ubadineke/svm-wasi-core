//! A minimal, mockable JSON-RPC client for the handful of Solana RPC
//! methods a build-only tool plugin needs — not a port of `solana-client`,
//! which assumes native sockets/TLS unavailable inside a wasm32-wasip2
//! component (the bounty's own "trap #2").
//!
//! The transport is a trait so `cargo test` mocks every response and never
//! touches the network. The real `wasi:http` transport lives in
//! [`waki_transport`] (wasm-only); [`mock::MockTransport`] replays canned
//! responses for host tests.
//!
//! Every method requests `encoding: "base64"` where applicable, so
//! [`AccountInfo`] is one consistent shape across `getAccountInfo`,
//! `getMultipleAccounts`, and `getTokenAccountsByOwner` — not three
//! different parsers for `base64` vs `jsonParsed` vs `base58`.

pub mod mock;
#[cfg(feature = "native-http")]
pub mod native_transport;
#[cfg(target_family = "wasm")]
pub mod waki_transport;

use crate::hash::Hash;
use crate::pubkey::Pubkey;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use serde_json::{json, Value};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, thiserror::Error)]
pub enum RpcError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("RPC error {code}: {message}")]
    Rpc { code: i64, message: String },
    #[error("unexpected response shape: {0}")]
    Decode(String),
}

/// The boundary a transport must implement: send a JSON-RPC 2.0 request,
/// return the raw response object (`{"result":...}` or `{"error":...}`),
/// or a transport-level error. Envelope parsing happens one level up in
/// [`RpcClient`], so the real transport and test mocks share one
/// implementation of it.
pub trait RpcTransport {
    fn send(&self, request: Value) -> Result<Value, RpcError>;
}

/// A fetched account, decoded from the RPC's `["<base64>", "base64"]`
/// `data` tuple. Mirrors `solana_account::Account`'s public fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AccountInfo {
    pub lamports: u64,
    pub data: Vec<u8>,
    pub owner: Pubkey,
    pub executable: bool,
    pub rent_epoch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockhashInfo {
    pub blockhash: Hash,
    pub last_valid_block_height: u64,
}

/// An SPL token amount, kept exactly as the RPC represents it — `amount` is
/// a decimal-string integer (can exceed `f64` precision, so it's not parsed
/// down to a number) and `ui_amount` is the display-scaled float the RPC
/// also provides (`None` on the rare account where it can't be computed).
#[derive(Clone, Debug, PartialEq)]
pub struct TokenAmount {
    pub amount: String,
    pub decimals: u8,
    pub ui_amount: Option<f64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenAccountEntry {
    pub pubkey: Pubkey,
    pub account: AccountInfo,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SimulateTransactionResult {
    pub err: Option<Value>,
    pub logs: Vec<String>,
    pub units_consumed: Option<u64>,
}

#[derive(Clone, Debug, PartialEq)]
pub struct SignatureStatus {
    pub slot: u64,
    pub confirmations: Option<u64>,
    pub err: Option<Value>,
    pub confirmation_status: Option<String>,
}

/// One entry from `getSignaturesForAddress` — a transaction that touched a
/// given address, newest first.
#[derive(Clone, Debug, PartialEq)]
pub struct SignatureInfo {
    pub signature: String,
    pub slot: u64,
    pub err: Option<Value>,
    pub memo: Option<String>,
    pub block_time: Option<i64>,
    pub confirmation_status: Option<String>,
}

fn decode_pubkey(value: &Value, field: &str) -> Result<Pubkey, RpcError> {
    let s = value
        .as_str()
        .ok_or_else(|| RpcError::Decode(format!("expected a string for `{field}`")))?;
    Pubkey::from_str(s).map_err(|e| RpcError::Decode(format!("invalid pubkey in `{field}`: {e}")))
}

fn require<'a>(value: &'a Value, field: &str) -> Result<&'a Value, RpcError> {
    value
        .get(field)
        .ok_or_else(|| RpcError::Decode(format!("missing `{field}`")))
}

fn decode_account_info(value: &Value) -> Result<AccountInfo, RpcError> {
    let lamports = require(value, "lamports")?
        .as_u64()
        .ok_or_else(|| RpcError::Decode("`lamports` is not a u64".into()))?;
    let owner = decode_pubkey(require(value, "owner")?, "owner")?;
    let executable = require(value, "executable")?.as_bool().unwrap_or(false);
    let rent_epoch = require(value, "rentEpoch")?
        .as_u64()
        .ok_or_else(|| RpcError::Decode("`rentEpoch` is not a u64".into()))?;
    let base64_str = require(value, "data")?
        .get(0)
        .and_then(Value::as_str)
        .ok_or_else(|| {
            RpcError::Decode(
                "expected `data` as [base64, \"base64\"] — request base64 encoding".into(),
            )
        })?;
    let data = BASE64
        .decode(base64_str)
        .map_err(|e| RpcError::Decode(format!("invalid base64 account data: {e}")))?;

    Ok(AccountInfo {
        lamports,
        data,
        owner,
        executable,
        rent_epoch,
    })
}

/// Wraps an [`RpcTransport`] with typed, JSON-RPC-2.0-envelope-aware
/// methods. One client per RPC endpoint; safe to share across calls
/// (each call gets its own monotonically increasing request id).
pub struct RpcClient<T: RpcTransport> {
    transport: T,
    next_id: AtomicU64,
}

impl<T: RpcTransport> RpcClient<T> {
    pub fn new(transport: T) -> Self {
        Self {
            transport,
            next_id: AtomicU64::new(1),
        }
    }

    /// Builds and sends one JSON-RPC 2.0 request, returning its `result` —
    /// or an [`RpcError::Rpc`] if the server responded with `error` instead.
    fn call(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let request = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let response = self.transport.send(request)?;

        if let Some(error) = response.get("error") {
            let code = error.get("code").and_then(Value::as_i64).unwrap_or(0);
            let message = error
                .get("message")
                .and_then(Value::as_str)
                .unwrap_or("unknown RPC error")
                .to_string();
            return Err(RpcError::Rpc { code, message });
        }

        response
            .get("result")
            .cloned()
            .ok_or_else(|| RpcError::Decode("response has neither `result` nor `error`".into()))
    }

    /// Most methods wrap their payload as `{"context": {...}, "value": ...}`;
    /// this pulls `value` out after `call`'s envelope handling.
    fn call_value(&self, method: &str, params: Value) -> Result<Value, RpcError> {
        let result = self.call(method, params)?;
        result
            .get("value")
            .cloned()
            .ok_or_else(|| RpcError::Decode(format!("`{method}` result missing `value`")))
    }

    pub fn get_latest_blockhash(&self) -> Result<BlockhashInfo, RpcError> {
        let value = self.call_value("getLatestBlockhash", json!([{"commitment": "confirmed"}]))?;
        let blockhash_str = require(&value, "blockhash")?
            .as_str()
            .ok_or_else(|| RpcError::Decode("`blockhash` is not a string".into()))?;
        let blockhash = Hash::from_str(blockhash_str)
            .map_err(|e| RpcError::Decode(format!("invalid blockhash: {e}")))?;
        let last_valid_block_height = require(&value, "lastValidBlockHeight")?
            .as_u64()
            .ok_or_else(|| RpcError::Decode("`lastValidBlockHeight` is not a u64".into()))?;
        Ok(BlockhashInfo {
            blockhash,
            last_valid_block_height,
        })
    }

    pub fn get_balance(&self, pubkey: &Pubkey) -> Result<u64, RpcError> {
        let value = self.call_value(
            "getBalance",
            json!([pubkey.to_string(), {"commitment": "confirmed"}]),
        )?;
        value
            .as_u64()
            .ok_or_else(|| RpcError::Decode("expected a u64 `value`".into()))
    }

    pub fn get_account_info(&self, pubkey: &Pubkey) -> Result<Option<AccountInfo>, RpcError> {
        let value = self.call_value(
            "getAccountInfo",
            json!([pubkey.to_string(), {"encoding": "base64", "commitment": "confirmed"}]),
        )?;
        if value.is_null() {
            return Ok(None);
        }
        decode_account_info(&value).map(Some)
    }

    pub fn get_multiple_accounts(
        &self,
        pubkeys: &[Pubkey],
    ) -> Result<Vec<Option<AccountInfo>>, RpcError> {
        let keys: Vec<String> = pubkeys.iter().map(Pubkey::to_string).collect();
        let value = self.call_value(
            "getMultipleAccounts",
            json!([keys, {"encoding": "base64", "commitment": "confirmed"}]),
        )?;
        let array = value
            .as_array()
            .ok_or_else(|| RpcError::Decode("expected an array `value`".into()))?;
        array
            .iter()
            .map(|entry| {
                if entry.is_null() {
                    Ok(None)
                } else {
                    decode_account_info(entry).map(Some)
                }
            })
            .collect()
    }

    pub fn get_token_account_balance(
        &self,
        token_account: &Pubkey,
    ) -> Result<TokenAmount, RpcError> {
        let value = self.call_value(
            "getTokenAccountBalance",
            json!([token_account.to_string(), {"commitment": "confirmed"}]),
        )?;
        let amount = require(&value, "amount")?
            .as_str()
            .ok_or_else(|| RpcError::Decode("`amount` is not a string".into()))?
            .to_string();
        let decimals = require(&value, "decimals")?
            .as_u64()
            .ok_or_else(|| RpcError::Decode("`decimals` is not a number".into()))?
            as u8;
        let ui_amount = value.get("uiAmount").and_then(Value::as_f64);
        Ok(TokenAmount {
            amount,
            decimals,
            ui_amount,
        })
    }

    pub fn get_token_accounts_by_owner(
        &self,
        owner: &Pubkey,
        mint: &Pubkey,
    ) -> Result<Vec<TokenAccountEntry>, RpcError> {
        let value = self.call_value(
            "getTokenAccountsByOwner",
            json!([
                owner.to_string(),
                {"mint": mint.to_string()},
                {"encoding": "base64", "commitment": "confirmed"},
            ]),
        )?;
        let array = value
            .as_array()
            .ok_or_else(|| RpcError::Decode("expected an array `value`".into()))?;
        array
            .iter()
            .map(|entry| {
                let pubkey = decode_pubkey(require(entry, "pubkey")?, "pubkey")?;
                let account = decode_account_info(require(entry, "account")?)?;
                Ok(TokenAccountEntry { pubkey, account })
            })
            .collect()
    }

    pub fn simulate_transaction(
        &self,
        transaction_base64: &str,
    ) -> Result<SimulateTransactionResult, RpcError> {
        let value = self.call_value(
            "simulateTransaction",
            json!([transaction_base64, {"encoding": "base64", "commitment": "confirmed", "sigVerify": false}]),
        )?;
        let err = value.get("err").cloned().filter(|v| !v.is_null());
        let logs = value
            .get("logs")
            .and_then(Value::as_array)
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let units_consumed = value.get("unitsConsumed").and_then(Value::as_u64);
        Ok(SimulateTransactionResult {
            err,
            logs,
            units_consumed,
        })
    }

    /// Returns the transaction signature (base58) on success. The bounty's
    /// custody ladder means a T1 ("Build") plugin should never call this —
    /// it returns an unsigned tx for a human or host to submit instead.
    ///
    /// Requests `preflightCommitment: "confirmed"` (matching
    /// [`Self::get_latest_blockhash`]'s commitment) rather than the RPC's
    /// `finalized` default — otherwise a blockhash fetched at `confirmed`
    /// can fail preflight with "Blockhash not found", since finalization
    /// lags confirmation by tens of slots. Verified against real devnet
    /// behavior, not just the docs.
    pub fn send_transaction(&self, transaction_base64: &str) -> Result<String, RpcError> {
        let result = self.call(
            "sendTransaction",
            json!([transaction_base64, {"encoding": "base64", "preflightCommitment": "confirmed"}]),
        )?;
        result
            .as_str()
            .map(str::to_string)
            .ok_or_else(|| RpcError::Decode("expected a string signature".into()))
    }

    pub fn get_signature_statuses(
        &self,
        signatures: &[String],
    ) -> Result<Vec<Option<SignatureStatus>>, RpcError> {
        let value = self.call_value(
            "getSignatureStatuses",
            json!([signatures, {"searchTransactionHistory": true}]),
        )?;
        let array = value
            .as_array()
            .ok_or_else(|| RpcError::Decode("expected an array `value`".into()))?;
        array
            .iter()
            .map(|entry| {
                if entry.is_null() {
                    return Ok(None);
                }
                let slot = require(entry, "slot")?
                    .as_u64()
                    .ok_or_else(|| RpcError::Decode("`slot` is not a u64".into()))?;
                let confirmations = entry.get("confirmations").and_then(Value::as_u64);
                let err = entry.get("err").cloned().filter(|v| !v.is_null());
                let confirmation_status = entry
                    .get("confirmationStatus")
                    .and_then(Value::as_str)
                    .map(String::from);
                Ok(Some(SignatureStatus {
                    slot,
                    confirmations,
                    err,
                    confirmation_status,
                }))
            })
            .collect()
    }

    /// Newest-first list of transactions that touched `address`. Unlike
    /// most other methods here, the result is a bare array — no
    /// `{context, value}` envelope — so this goes through [`Self::call`]
    /// directly, not [`Self::call_value`]. `until` (a signature) bounds the
    /// search to everything newer than it, for cursor-style pagination
    /// across repeated polls.
    pub fn get_signatures_for_address(
        &self,
        address: &Pubkey,
        until: Option<&str>,
    ) -> Result<Vec<SignatureInfo>, RpcError> {
        let mut opts = serde_json::Map::new();
        opts.insert("commitment".to_string(), json!("confirmed"));
        if let Some(until) = until {
            opts.insert("until".to_string(), json!(until));
        }
        let result = self.call(
            "getSignaturesForAddress",
            json!([address.to_string(), opts]),
        )?;
        let array = result
            .as_array()
            .ok_or_else(|| RpcError::Decode("expected an array result".into()))?;
        array
            .iter()
            .map(|entry| {
                let signature = require(entry, "signature")?
                    .as_str()
                    .ok_or_else(|| RpcError::Decode("`signature` is not a string".into()))?
                    .to_string();
                let slot = require(entry, "slot")?
                    .as_u64()
                    .ok_or_else(|| RpcError::Decode("`slot` is not a u64".into()))?;
                let err = entry.get("err").cloned().filter(|v| !v.is_null());
                let memo = entry.get("memo").and_then(Value::as_str).map(String::from);
                let block_time = entry.get("blockTime").and_then(Value::as_i64);
                let confirmation_status = entry
                    .get("confirmationStatus")
                    .and_then(Value::as_str)
                    .map(String::from);
                Ok(SignatureInfo {
                    signature,
                    slot,
                    err,
                    memo,
                    block_time,
                    confirmation_status,
                })
            })
            .collect()
    }

    /// Used to size the lamports a new nonce/token account needs to be
    /// rent-exempt (e.g. 80 bytes for a nonce account, 165 for an SPL Token
    /// account) before a `create_account` instruction.
    pub fn get_minimum_balance_for_rent_exemption(&self, data_len: usize) -> Result<u64, RpcError> {
        let result = self.call("getMinimumBalanceForRentExemption", json!([data_len]))?;
        result
            .as_u64()
            .ok_or_else(|| RpcError::Decode("expected a u64 result".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::mock::MockTransport;
    use super::*;

    #[test]
    fn rpc_error_response_surfaces_code_and_message() {
        let transport = MockTransport::new(vec![
            json!({"error": {"code": -32602, "message": "Invalid param: WrongSize"}}),
        ]);
        let client = RpcClient::new(transport);

        let err = client
            .get_balance(&Pubkey::new_from_array([1; 32]))
            .unwrap_err();
        match err {
            RpcError::Rpc { code, message } => {
                assert_eq!(code, -32602);
                assert_eq!(message, "Invalid param: WrongSize");
            }
            other => panic!("expected RpcError::Rpc, got {other:?}"),
        }
    }

    #[test]
    fn transport_failure_propagates_without_panicking() {
        let transport = MockTransport::new(vec![]); // no responses queued
        let client = RpcClient::new(transport);
        assert!(client
            .get_balance(&Pubkey::new_from_array([1; 32]))
            .is_err());
    }

    #[test]
    fn get_account_info_returns_none_for_missing_account() {
        // A missing account's `value` is `null`, but `result` itself is
        // still the usual `{context, value}` object — not `result: null`.
        let transport = MockTransport::ok(vec![json!({"context": {"slot": 1}, "value": null})]);
        let client = RpcClient::new(transport);
        let account = client
            .get_account_info(&Pubkey::new_from_array([1; 32]))
            .unwrap();
        assert_eq!(account, None);
    }

    #[test]
    fn request_ids_increment_across_calls() {
        // Two calls sharing one client must not reuse the same JSON-RPC id.
        let transport = MockTransport::ok(vec![json!(1_000_000u64), json!(2_000_000u64)]);
        let client = RpcClient::new(transport);
        let a = client.get_minimum_balance_for_rent_exemption(80).unwrap();
        let b = client.get_minimum_balance_for_rent_exemption(165).unwrap();
        assert_eq!((a, b), (1_000_000, 2_000_000));

        let received = client.transport.received();
        let id_a = received[0]["id"].as_u64().unwrap();
        let id_b = received[1]["id"].as_u64().unwrap();
        assert_ne!(id_a, id_b);
        assert_eq!(received[0]["jsonrpc"], "2.0");
        assert_eq!(received[0]["method"], "getMinimumBalanceForRentExemption");
    }

    /// Real, documented Solana JSON-RPC response shapes
    /// (`https://solana.com/docs/rpc/http`), hand-built against the
    /// schema. Reuses real mainnet pubkeys/blockhash already verified
    /// elsewhere in this crate (see `pubkey::tests::
    /// find_program_address_known_answer_mainnet_ata`).
    mod fixtures {
        use super::*;

        const USDC_MINT: &str = "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v";
        const TOKEN_PROGRAM: &str = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
        const ATA: &str = "BmeV7UWExZeSboQXYW4biUVEx2SyYDVTdWhHoQEQcUFu";
        const OWNER: &str = "5Q544fKrFoe6tsEbD7S8EmxGTJYAKtTVhAW5Q5pge4j1";

        #[test]
        fn parses_get_latest_blockhash() {
            let transport = MockTransport::ok(vec![json!({
                "context": {"slot": 433648265},
                "value": {
                    "blockhash": "EETubP5AKHgjPAhzPAFcb8BAY1hMH639CWCFTqi3hq1k",
                    "lastValidBlockHeight": 275_123_456u64,
                }
            })]);
            let client = RpcClient::new(transport);

            let info = client.get_latest_blockhash().unwrap();
            assert_eq!(
                info.blockhash.to_string(),
                "EETubP5AKHgjPAhzPAFcb8BAY1hMH639CWCFTqi3hq1k"
            );
            assert_eq!(info.last_valid_block_height, 275_123_456);
        }

        #[test]
        fn parses_get_account_info_for_the_known_ata() {
            // 165 bytes of SPL Token account data, base64-encoded — shape
            // only (all-zero payload); the byte-level Token account layout
            // itself is out of scope for the RPC client, which just hands
            // back raw bytes for the caller to interpret.
            let raw_data = vec![0u8; 165];
            let encoded = BASE64.encode(&raw_data);

            let transport = MockTransport::ok(vec![json!({
                "context": {"slot": 433648265},
                "value": {
                    "lamports": 2_039_280u64,
                    "owner": TOKEN_PROGRAM,
                    "executable": false,
                    "rentEpoch": 18_446_744_073_709_551_615u64, // u64::MAX, as real accounts report
                    "data": [encoded, "base64"],
                    "space": 165,
                }
            })]);
            let client = RpcClient::new(transport);

            let account = client
                .get_account_info(&Pubkey::from_str(ATA).unwrap())
                .unwrap()
                .unwrap();
            assert_eq!(account.lamports, 2_039_280);
            assert_eq!(account.owner, Pubkey::from_str(TOKEN_PROGRAM).unwrap());
            assert_eq!(account.rent_epoch, u64::MAX);
            assert_eq!(account.data, raw_data);
        }

        #[test]
        fn parses_get_token_account_balance() {
            let transport = MockTransport::ok(vec![json!({
                "context": {"slot": 433648265},
                "value": {"amount": "6131218", "decimals": 6, "uiAmount": 6.131218, "uiAmountString": "6.131218"}
            })]);
            let client = RpcClient::new(transport);

            let balance = client
                .get_token_account_balance(&Pubkey::from_str(ATA).unwrap())
                .unwrap();
            assert_eq!(balance.amount, "6131218");
            assert_eq!(balance.decimals, 6);
            assert_eq!(balance.ui_amount, Some(6.131218));
        }

        #[test]
        fn parses_get_token_accounts_by_owner_with_two_entries() {
            let entry = |pubkey: &str, lamports: u64| {
                json!({
                    "pubkey": pubkey,
                    "account": {
                        "lamports": lamports,
                        "owner": TOKEN_PROGRAM,
                        "executable": false,
                        "rentEpoch": 18_446_744_073_709_551_615u64,
                        "data": [BASE64.encode([0u8; 165]), "base64"],
                        "space": 165,
                    }
                })
            };
            let transport = MockTransport::ok(vec![json!({
                "context": {"slot": 433648265},
                "value": [entry(ATA, 2_039_280), entry("14ivbuCkynkVJ1n1NVj4WyAFGXywxvS4TFzujP2o7bi", 2_039_280)],
            })]);
            let client = RpcClient::new(transport);

            let entries = client
                .get_token_accounts_by_owner(
                    &Pubkey::from_str(OWNER).unwrap(),
                    &Pubkey::from_str(USDC_MINT).unwrap(),
                )
                .unwrap();
            assert_eq!(entries.len(), 2);
            assert_eq!(entries[0].pubkey, Pubkey::from_str(ATA).unwrap());
        }

        #[test]
        fn parses_simulate_transaction_success() {
            let transport = MockTransport::ok(vec![json!({
                "context": {"slot": 433648265},
                "value": {
                    "err": null,
                    "logs": ["Program 11111111111111111111111111111111 invoke [1]", "Program 11111111111111111111111111111111 success"],
                    "accounts": null,
                    "unitsConsumed": 150u64,
                    "returnData": null,
                }
            })]);
            let client = RpcClient::new(transport);

            let result = client.simulate_transaction("base64tx==").unwrap();
            assert_eq!(result.err, None);
            assert_eq!(result.logs.len(), 2);
            assert_eq!(result.units_consumed, Some(150));
        }

        #[test]
        fn parses_simulate_transaction_failure_preserving_err_value() {
            let transport = MockTransport::ok(vec![json!({
                "context": {"slot": 433648265},
                "value": {
                    "err": {"InstructionError": [0, "Custom", 1]},
                    "logs": ["Program 11111111111111111111111111111111 invoke [1]", "Program 11111111111111111111111111111111 failed: custom program error: 0x1"],
                    "unitsConsumed": 0u64,
                }
            })]);
            let client = RpcClient::new(transport);

            let result = client.simulate_transaction("base64tx==").unwrap();
            assert!(result.err.is_some());
        }

        #[test]
        fn parses_get_signature_statuses_with_a_null_entry() {
            let transport = MockTransport::ok(vec![json!({
                "context": {"slot": 433648265},
                "value": [
                    {"slot": 433648200u64, "confirmations": null, "err": null, "confirmationStatus": "finalized"},
                    null,
                ]
            })]);
            let client = RpcClient::new(transport);

            let statuses = client
                .get_signature_statuses(&["sig1".to_string(), "sig2".to_string()])
                .unwrap();
            assert_eq!(statuses.len(), 2);
            let first = statuses[0].as_ref().unwrap();
            assert_eq!(first.confirmation_status.as_deref(), Some("finalized"));
            assert_eq!(statuses[1], None);
        }

        #[test]
        fn parses_get_signatures_for_address_bare_array_result() {
            // No {context, value} envelope for this method — the result is
            // the array itself.
            let transport = MockTransport::ok(vec![json!([
                {
                    "signature": "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW",
                    "slot": 433648265u64,
                    "err": null,
                    "memo": "invoice LOGO-04",
                    "blockTime": 1_798_000_000i64,
                    "confirmationStatus": "confirmed",
                },
            ])]);
            let client = RpcClient::new(transport);

            let signatures = client
                .get_signatures_for_address(&Pubkey::from_str(ATA).unwrap(), None)
                .unwrap();

            assert_eq!(signatures.len(), 1);
            assert_eq!(signatures[0].memo.as_deref(), Some("invoice LOGO-04"));
            assert_eq!(
                signatures[0].confirmation_status.as_deref(),
                Some("confirmed")
            );
            assert_eq!(signatures[0].err, None);
        }

        #[test]
        fn get_signatures_for_address_returns_empty_for_an_unused_address() {
            let transport = MockTransport::ok(vec![json!([])]);
            let client = RpcClient::new(transport);

            let signatures = client
                .get_signatures_for_address(&Pubkey::from_str(ATA).unwrap(), None)
                .unwrap();

            assert!(signatures.is_empty());
        }

        #[test]
        fn get_signatures_for_address_sends_until_when_provided() {
            let transport = MockTransport::ok(vec![json!([])]);
            let client = RpcClient::new(transport);

            client
                .get_signatures_for_address(&Pubkey::from_str(ATA).unwrap(), Some("sig123"))
                .unwrap();

            let received = client.transport.received();
            assert_eq!(received[0]["params"][1]["until"], "sig123");
        }

        #[test]
        fn parses_send_transaction_signature() {
            let transport = MockTransport::ok(vec![json!(
                "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW"
            )]);
            let client = RpcClient::new(transport);
            let sig = client.send_transaction("base64tx==").unwrap();
            assert_eq!(sig, "5VERv8NMvzbJMEkV8xnrLkEaWRtSz9CosKDYjCJjBRnbJLgp8uirBgmQpjKhoR4tjF3ZpRzrFmBV6UjKdiSZkQUW");
        }

        #[test]
        fn parses_get_minimum_balance_for_rent_exemption() {
            let transport = MockTransport::ok(vec![json!(890_880u64)]);
            let client = RpcClient::new(transport);
            assert_eq!(
                client.get_minimum_balance_for_rent_exemption(165).unwrap(),
                890_880
            );
        }
    }
}
