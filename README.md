# svm-wasi-core

A pure-Rust Solana core for `wasm32-wasip2` WASI components — pubkeys, PDAs,
instruction encoding, transaction construction, and RPC, with zero
`solana-sdk` or `solana-client` dependency.

## Why this exists

`solana-sdk` and `solana-client` assume a native environment: they open
their own sockets and do their own TLS. Neither compiles (or makes sense)
inside a `wasm32-wasip2` WASI component, where the only way out to the
network is a host-provided `wasi:http` interface. This crate is the
substrate that actually works in that sandbox — built for a
[ZeroClaw](https://github.com/zeroclaw-labs/zeroclaw) plugin, but nothing
about it is ZeroClaw-specific. Anything targeting `wasm32-wasip2` that needs
to build, sign, or submit a Solana transaction can use this directly.

It is **not** a port of `solana-sdk`. It's scoped to exactly what a
transaction-building component needs: identity, a handful of program
integrations, transaction/message construction, and a minimal RPC client.
Nothing else.

## Module map

| Module | What it is |
|---|---|
| `pubkey` | `Pubkey`, base58 (de)serialization, PDA derivation (`find_program_address`/`create_program_address`) — including the ed25519 off-curve check most implementations get subtly wrong |
| `hash` | `Hash` (blockhashes / durable-nonce values) — same base58 shape as `Pubkey` |
| `signature` | `Signature`, the 64-byte transaction-signature type |
| `shortvec` | Solana's compact-u16 short-vec wire encoding — not borsh, not standard LEB128, its own scheme |
| `instruction` | Hand-rolled instruction encoding for System, SPL Token / Token-2022, Associated Token Account, Memo, and Solana Foundation's Subscriptions & Allowances program |
| `message` | Legacy `Message` and versioned `MessageV0` (with address lookup table support), full account-compilation/dedup logic ported from the real runtime's own algorithm |
| `transaction` | `Transaction` / `VersionedTransaction` — the actual signable envelope (signature array + message), not just a bare message |
| `nonce` | Durable-nonce account state parsing — the primitive that makes approval-gated payments survive blockhash expiry |
| `token_state` | SPL Token / Token-2022 mint and account state parsing, including extension TLV data (transfer fee, permanent delegate, transfer hook) |
| `subscription_state` | Account state parsing for the Subscriptions & Allowances program (`SubscriptionAuthority`, `RecurringDelegation`) |
| `rpc` | A minimal, mockable JSON-RPC client (~12 methods) — `mock` for host tests, `waki_transport` (wasm-only) for the real `wasi:http` path, `native_transport` (feature-gated) for off-host tooling |
| `shaping` | Generic RPC-response compression, so a plugin doesn't have to hand a raw multi-KB JSON blob back to an LLM |
| `sign` | Ed25519 signing (feature-gated, see below) |

## Design principles

- **Pure core, no wasm dependency.** Nothing in this crate touches
  `wit-bindgen` or any wasm-only API by default. `cargo test` runs the whole
  suite natively, no wasm toolchain required, no live network — every RPC
  method is tested against a mock transport with real, documented response
  shapes.
- **Verified against primary sources, not memory.** Every instruction byte
  layout, PDA seed scheme, and account state layout in this crate was
  checked against the actual program source it targets (cloned and read
  directly), not reconstructed from a description or an announcement post.
  Several pieces are additionally verified against **real Solana devnet
  behavior** — including one case where a documented on-chain program
  behavior did not hold up under real testing, and the fix here reflects
  what's actually true on-chain, not what the docs claimed.
- **Panics don't happen.** A panic inside a `wasm32-wasip2` component traps
  the whole guest instance — the wrong failure mode for something that's
  supposed to return `Result<ToolResult, String>`. Fallible paths return
  `Result` throughout, including PDA derivation and message compilation,
  which upstream `solana-program` itself implements with panicking APIs.

## Feature flags

| Feature | Default | Pulls in | For |
|---|---|---|---|
| *(none)* | — | — | Building transactions, reading state, talking to RPC — everything a T0/T1 (read/build) plugin needs |
| `sign` | off | `ed25519-dalek` | Loading a keypair and producing real signatures — off-chain tooling, test harnesses, or a T2 plugin holding a scoped session key. Never pulled in by a plugin that only builds unsigned transactions. |
| `native-http` | off | `ureq` | A blocking, non-wasm HTTP transport for scripts/tests that run on the host rather than inside a component (`waki`/`wasi:http` only compiles under `wasm32-wasip2`) |

## Using it

This crate is not published to crates.io (deliberately — see
`publish = false`). Depend on it via git, pinned to a tag or commit, the
same way this ecosystem's own docs recommend pulling host crates for
plugin integration testing:

```toml
[dependencies]
svm-wasi-core = { git = "https://github.com/ubadineke/svm-wasi-core", tag = "v0.1.0" }
```

Building for `wasm32-wasip2`:

```bash
rustup target add wasm32-wasip2
cargo build --target wasm32-wasip2 --release
```

Running the test suite (host-only, no wasm toolchain, no network):

```bash
cargo test
cargo test --features sign,native-http
```

## Status

Actively evolving. The four programs currently covered (System, SPL
Token/Token-2022, Associated Token Account, Memo) plus Solana Foundation's
Subscriptions & Allowances program were scoped to what specific plugins
built on this crate actually needed — not an attempt at full `solana-sdk`
parity. More program integrations get added the same way: only when a real
consumer needs one, each verified against that program's own source before
anything is encoded.

## License

MIT — see [LICENSE](LICENSE).
