//! Generates a fresh stealth meta-address keypair (scan + spend). Run this
//! once, at setup, on your own machine — this is the one moment
//! `spend_privkey` is ever in plaintext anywhere. Copy both private keys
//! into your own secure storage (password manager, encrypted note) before
//! doing anything else. See `KEY_CUSTODY_FLOW.md` at the repo root for the
//! full lifecycle this fits into.
//!
//! ```text
//! cargo run --example generate_stealth_meta_address --features stealth
//! ```

use svm_wasi_core::stealth::{generate_keypair, scalar_to_hex};

fn main() {
    let (scan_priv, scan_pub) = generate_keypair();
    let (spend_priv, spend_pub) = generate_keypair();

    println!("scan_privkey  = {}", scalar_to_hex(&scan_priv));
    println!("scan_pubkey   = {scan_pub}");
    println!("spend_privkey = {}", scalar_to_hex(&spend_priv));
    println!("spend_pubkey  = {spend_pub}");
    println!();
    println!("Copy scan_privkey and spend_privkey into your own secure storage now.");
    println!("This is the only time either will ever be shown in plaintext.");
    println!("scan_pubkey/spend_pubkey are public — safe to publish as your meta-address.");
}
