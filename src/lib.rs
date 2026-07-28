//! wasm32-wasip2 Solana convenience layer, built on the modular
//! `solana-*`/`spl-*-interface` crates — verified by build to compile clean
//! for this target.
//!
//! Feature notes: `solana-pubkey` needs `curve25519` + `sha2` for PDA
//! derivation; `solana-message`/`solana-nonce` use `serde`, not `wincode`
//! (which pulls in `wit-bindgen`/`wasip2`); `solana-system-interface` needs
//! `bincode` for its instruction builders to exist at all.
//!
//! Not replaced by modular crates (no equivalent exists): the `rpc` waki
//! transport, `nonce`/`message`'s durable-nonce helpers, `shaping`,
//! `transaction` (no unsigned constructor upstream), and
//! `instruction::{associated_token_account, subscriptions}`.

pub mod hash;
pub mod instruction;
pub mod message;
pub mod nonce;
pub mod pubkey;
pub mod rpc;
pub mod shaping;
#[cfg(feature = "sign")]
pub mod sign;
pub mod signature;
#[cfg(feature = "stealth")]
pub mod stealth;
pub mod subscription_state;
pub mod token_state;
pub mod transaction;

pub use hash::{Hash, ParseHashError};
pub use message::{AddressLookupTableAccount, CompileError, Message, MessageHeader, MessageV0};
pub use nonce::{NonceAccount, NonceData, NonceError, NonceState};
pub use pubkey::{ParsePubkeyError, Pubkey, PubkeyError};
pub use rpc::{RpcClient, RpcError, RpcTransport};
#[cfg(feature = "sign")]
pub use sign::{Keypair, SignError};
pub use signature::{ParseSignatureError, Signature};
#[cfg(feature = "stealth")]
pub use stealth::StealthError;
pub use subscription_state::{RecurringDelegation, SubscriptionAuthority, SubscriptionStateError};
pub use token_state::{
    find_permanent_delegate, find_transfer_fee_config, find_transfer_hook, AccountState, Mint,
    TokenAccount, TokenStateError, TransferFee, TransferFeeConfig, TransferHookConfig,
};
pub use transaction::{Transaction, VersionedTransaction};
