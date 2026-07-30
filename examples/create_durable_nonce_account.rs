//! One-time setup: creates and funds a durable nonce account, so
//! `stealth-sweep-build` never has to race a ~60-90 second blockhash
//! expiry against a human approval queue. Run this once, on your own
//! machine, with an ordinary Solana wallet keypair file (the standard
//! `solana-keygen` on-disk format — 64 bytes, seed || pubkey, as a JSON
//! array). That same keypair becomes the nonce account's authority, and
//! the external signer needs it again to co-sign every sweep.
//!
//! ```text
//! cargo run --example create_durable_nonce_account --features sign,native-http -- \
//!     --rpc-url https://api.devnet.solana.com \
//!     --payer-keypair ~/path/to/keypair.json
//! ```

use std::process::ExitCode;

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use svm_wasi_core::instruction::system;
use svm_wasi_core::message::Message;
use svm_wasi_core::nonce::NonceState;
use svm_wasi_core::rpc::native_transport::NativeHttpTransport;
use svm_wasi_core::sign::Keypair;
use svm_wasi_core::{RpcClient, Transaction};

struct Args {
    rpc_url: String,
    payer_keypair_path: String,
}

fn parse_args() -> Result<Args, String> {
    let mut rpc_url = None;
    let mut payer_keypair_path = None;

    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--rpc-url" => rpc_url = Some(value),
            "--payer-keypair" => payer_keypair_path = Some(value),
            other => return Err(format!("unrecognized flag {other}")),
        }
    }

    Ok(Args {
        rpc_url: rpc_url.ok_or("missing --rpc-url")?,
        payer_keypair_path: payer_keypair_path.ok_or("missing --payer-keypair")?,
    })
}

fn load_keypair_file(path: &str) -> Result<Keypair, String> {
    let contents =
        std::fs::read_to_string(path).map_err(|e| format!("could not read {path}: {e}"))?;
    let bytes: Vec<u8> = serde_json::from_str(&contents)
        .map_err(|e| format!("{path} is not a solana-keygen JSON keypair file: {e}"))?;
    Keypair::from_bytes(&bytes).map_err(|e| format!("{path}: {e}"))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!("usage: create_durable_nonce_account --rpc-url <url> --payer-keypair <path>");
            return ExitCode::FAILURE;
        }
    };

    let payer = match load_keypair_file(&args.payer_keypair_path) {
        Ok(kp) => kp,
        Err(e) => {
            eprintln!("error loading payer keypair: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The nonce account's own key only ever signs once, right here, to
    // prove ownership of the fresh address at creation — never needed
    // again afterward. Advancing/withdrawing later only needs the
    // authority (the payer, in this setup), not this key.
    let nonce_signing_key = SigningKey::generate(&mut OsRng);
    let mut nonce_kp_bytes = [0u8; 64];
    nonce_kp_bytes[..32].copy_from_slice(&nonce_signing_key.to_bytes());
    nonce_kp_bytes[32..].copy_from_slice(nonce_signing_key.verifying_key().as_bytes());
    let nonce_keypair = Keypair::from_bytes(&nonce_kp_bytes).expect("just-generated key is valid");

    let rpc = RpcClient::new(NativeHttpTransport::new(args.rpc_url.as_str()));

    let lamports = match rpc.get_minimum_balance_for_rent_exemption(NonceState::size()) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("could not fetch rent-exempt minimum: {e}");
            return ExitCode::FAILURE;
        }
    };

    let instructions = system::create_nonce_account(
        &payer.pubkey(),
        &nonce_keypair.pubkey(),
        &payer.pubkey(),
        lamports,
    );

    let blockhash = match rpc.get_latest_blockhash() {
        Ok(info) => info.blockhash,
        Err(e) => {
            eprintln!("could not fetch a blockhash: {e}");
            return ExitCode::FAILURE;
        }
    };

    let mut message = Message::new(&instructions, Some(&payer.pubkey()));
    message.recent_blockhash = blockhash;
    let mut tx = Transaction::new_unsigned(message);

    if let Err(e) = tx.try_sign(&payer) {
        eprintln!("payer failed to sign: {e}");
        return ExitCode::FAILURE;
    }
    if let Err(e) = tx.try_sign(&nonce_keypair) {
        eprintln!("nonce account failed to sign: {e}");
        return ExitCode::FAILURE;
    }

    match rpc.send_transaction(&tx.to_base64()) {
        Ok(signature) => {
            println!("Created durable nonce account.");
            println!("nonce_account   = {}", nonce_keypair.pubkey());
            println!("nonce_authority = {}", payer.pubkey());
            println!("transaction signature = {signature}");
            println!(
                "\nPut both values into stealth-sweep-build's config as `nonce_account` and \
                 `nonce_authority`. Keep {} — the external signer needs it again for every sweep.",
                args.payer_keypair_path
            );
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("broadcast failed: {e}");
            ExitCode::FAILURE
        }
    }
}
