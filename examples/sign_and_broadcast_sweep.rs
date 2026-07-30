//! The external signer: recovers a stealth one-time private key and signs a
//! `build_stealth_sweep` proposal with it. Native-only, run by the operator
//! on their own machine — never a plugin, never touched by ZeroClaw or an
//! agent. See `KEY_CUSTODY_FLOW.md` at the repo root for the full lifecycle
//! this fits into.
//!
//! `scan_privkey`/`spend_privkey` are read from masked stdin prompts, never
//! CLI args (shell history) or env vars. Everything else is a plain arg.
//!
//! ```text
//! cargo run --example sign_and_broadcast_sweep --features stealth-sign,native-http -- \
//!     --rpc-url https://api.devnet.solana.com \
//!     --ephemeral-pubkey <base58> \
//!     --transaction-base64 <base64 from build_stealth_sweep>
//! ```

use std::io::{self, Write};
use std::process::ExitCode;
use std::str::FromStr;

use svm_wasi_core::rpc::native_transport::NativeHttpTransport;
use svm_wasi_core::stealth::{recover_one_time_privkey, scalar_from_hex};
use svm_wasi_core::stealth_sign::sign_with_recovered_key;
use svm_wasi_core::{Pubkey, RpcClient, VersionedTransaction};

struct Args {
    rpc_url: String,
    ephemeral_pubkey: Pubkey,
    transaction_base64: String,
}

fn parse_args() -> Result<Args, String> {
    let mut rpc_url = None;
    let mut ephemeral_pubkey = None;
    let mut transaction_base64 = None;

    let mut iter = std::env::args().skip(1);
    while let Some(flag) = iter.next() {
        let value = iter.next().ok_or_else(|| format!("{flag} needs a value"))?;
        match flag.as_str() {
            "--rpc-url" => rpc_url = Some(value),
            "--ephemeral-pubkey" => {
                ephemeral_pubkey =
                    Some(Pubkey::from_str(&value).map_err(|e| format!("--ephemeral-pubkey: {e}"))?)
            }
            "--transaction-base64" => transaction_base64 = Some(value),
            other => return Err(format!("unrecognized flag {other}")),
        }
    }

    Ok(Args {
        rpc_url: rpc_url.ok_or("missing --rpc-url")?,
        ephemeral_pubkey: ephemeral_pubkey.ok_or("missing --ephemeral-pubkey")?,
        transaction_base64: transaction_base64.ok_or("missing --transaction-base64")?,
    })
}

fn prompt_line(label: &str) -> io::Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_string())
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("error: {e}");
            eprintln!(
                "usage: sign_and_broadcast_sweep --rpc-url <url> --ephemeral-pubkey <base58> \
                 --transaction-base64 <base64>"
            );
            return ExitCode::FAILURE;
        }
    };

    let scan_privkey_hex = match rpassword::prompt_password("scan_privkey (hex, hidden): ") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error reading scan_privkey: {e}");
            return ExitCode::FAILURE;
        }
    };
    let spend_privkey_hex = match rpassword::prompt_password("spend_privkey (hex, hidden): ") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error reading spend_privkey: {e}");
            return ExitCode::FAILURE;
        }
    };

    let scan_priv = match scalar_from_hex(scan_privkey_hex.trim()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("invalid scan_privkey: {e}");
            return ExitCode::FAILURE;
        }
    };
    let spend_priv = match scalar_from_hex(spend_privkey_hex.trim()) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("invalid spend_privkey: {e}");
            return ExitCode::FAILURE;
        }
    };

    let t = match recover_one_time_privkey(&scan_priv, &args.ephemeral_pubkey, &spend_priv) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("could not recover one-time key: {e}");
            return ExitCode::FAILURE;
        }
    };
    let one_time_point = &t * curve25519_dalek::constants::ED25519_BASEPOINT_TABLE;
    let one_time_pubkey = Pubkey::new_from_array(one_time_point.compress().to_bytes());

    let mut tx = match VersionedTransaction::try_from_base64(&args.transaction_base64) {
        Ok(tx) => tx,
        Err(e) => {
            eprintln!("could not parse --transaction-base64: {e}");
            return ExitCode::FAILURE;
        }
    };

    let message_bytes = tx.message_bytes_to_sign();
    let signature = match sign_with_recovered_key(&t, &message_bytes) {
        Ok(sig) => sig,
        Err(e) => {
            eprintln!("signing failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The real correctness check: if the recovered key's pubkey isn't one
    // of this transaction's required signers, either the wrong keys or the
    // wrong ephemeral pubkey were given — abort rather than sign nothing
    // useful.
    if let Err(e) = tx.insert_signature(&one_time_pubkey, signature) {
        eprintln!(
            "recovered key ({one_time_pubkey}) is not a required signer of this transaction: {e}"
        );
        eprintln!(
            "double-check --ephemeral-pubkey matches the invoice this sweep is for, and that \
             scan_privkey/spend_privkey are the pair that produced its meta-address."
        );
        return ExitCode::FAILURE;
    }

    println!("Recovered one-time signer: {one_time_pubkey}");
    println!("Signed transaction (base64):\n{}", tx.to_base64());

    let rpc = RpcClient::new(NativeHttpTransport::new(args.rpc_url.as_str()));

    println!("\nSimulating against {}...", args.rpc_url);
    let sim = match rpc.simulate_transaction(&tx.to_base64()) {
        Ok(sim) => sim,
        Err(e) => {
            eprintln!("simulation request failed: {e}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(err) = &sim.err {
        println!("Simulation FAILED: {err}");
        for log in &sim.logs {
            println!("  {log}");
        }
        println!("Not broadcasting a transaction that fails simulation.");
        return ExitCode::FAILURE;
    }
    println!(
        "Simulation succeeded (units consumed: {}).",
        sim.units_consumed
            .map(|u| u.to_string())
            .unwrap_or_else(|| "unknown".to_string())
    );

    let confirmation = match prompt_line("\nBroadcast this transaction? Type 'yes' to confirm: ") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error reading confirmation: {e}");
            return ExitCode::FAILURE;
        }
    };
    if confirmation != "yes" {
        println!("Not broadcasting. The signed transaction above can be submitted manually later.");
        return ExitCode::SUCCESS;
    }

    match rpc.send_transaction(&tx.to_base64()) {
        Ok(signature) => {
            println!("Broadcast. Transaction signature: {signature}");
            if args.rpc_url.contains("devnet") {
                println!("https://explorer.solana.com/tx/{signature}?cluster=devnet");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("broadcast failed: {e}");
            ExitCode::FAILURE
        }
    }
}
