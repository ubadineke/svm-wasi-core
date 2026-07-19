# Deferred: `anchor` feature (borsh + Anchor discriminator)

Status: **not implemented, deliberately deferred**. Implement + test only once a
plugin built on this crate actually needs to encode an instruction for an
Anchor-based program (e.g. `jupiter-swap-build`, or any Track B DeFi
integration — Jupiter/Kamino/MarginFi/Drift are all Anchor programs).

## Why this exists

BOUNTY.md's Track E description lists `borsh` alongside `bs58` as expected
tooling. This crate deliberately does not depend on it: none of the four
programs currently covered (System, SPL Token/Token-2022, Memo) use borsh on
the wire.

- System Program: bincode-style, 4-byte LE `u32` variant discriminant.
- SPL Token: hand-packed, 1-byte tag.
- Memo: raw UTF-8 bytes, no discriminant at all.
- Token-2022 extensions: bespoke TLV (2-byte LE type + 2-byte LE length + value).
- Borsh's own conventions (1-byte enum tag, fixed 4-byte `u32` Vec-length
  prefix, 1-byte Option tag) match *none* of the above — confirmed against
  each program's real source, not assumed. Solana's `compact-u16` short-vec
  (1–3 variable bytes) is a different scheme from borsh's Vec encoding, which
  is exactly the conflation CONTEXT.md calls out as a trap.

So adding borsh as a general-purpose encoder here would be actively wrong,
not just unused.

## Where borsh actually *is* correct

Anchor-based programs (the large majority of Solana DeFi, including every
Track B name in the bounty) use:

- An **8-byte instruction discriminator**: `sha256("global:<ix_name>")[0..8]`
  (not borsh's own enum-tagging convention — Anchor computes this itself).
- **Borsh-serialized args** immediately following that discriminator.

This is a real, narrow, correct use of borsh — just not for the programs
already in scope.

## The deferred design

A small, default-off `anchor` feature (same pattern as `sign` in
`Cargo.toml`):

```rust
// src/anchor.rs, feature = "anchor"
pub fn anchor_discriminator(namespace_and_name: &str) -> [u8; 8] {
    // sha256(namespace_and_name)[0..8], e.g. namespace_and_name = "global:swap"
}

// Thin re-export / passthrough — callers derive BorshSerialize on their own
// args struct and call this to assemble the full instruction data:
pub fn anchor_instruction_data(discriminator: [u8; 8], args: &impl borsh::BorshSerialize) -> Vec<u8> {
    // discriminator ++ borsh::to_vec(args)
}
```

- `[dependencies] borsh = { version = "...", optional = true }`, gated under
  `anchor = ["dep:borsh"]`.
- Lives entirely outside the default feature set — a plugin that never
  touches an Anchor program (e.g. `spl-transfer-build`) never pulls it in.

## Test plan for when it's implemented

- Known-answer test for `anchor_discriminator`: compute
  `sha256("global:<name>")[0..8]` independently (e.g. a from-scratch Python
  cross-check, same rigor as the PDA known-answer test) for a real,
  documented Anchor instruction name and assert the exact 8 bytes — not just
  a self-consistency round-trip against our own sha2 usage.
- A round-trip test: define a small `#[derive(BorshSerialize)]` args struct,
  call `anchor_instruction_data`, and assert the byte layout matches a
  hand-assembled expected buffer (discriminator ++ field bytes in
  declaration order).
- If/when a specific Anchor program's real instruction is targeted (e.g.
  Jupiter's `swap`), verify the discriminator against that program's actual
  IDL/source rather than assuming the naming convention — same source-first
  rigor applied to System/Token/Memo elsewhere in this crate.

## Trigger to pick this back up

Only when a second plugin is actually chosen that CPIs into an Anchor
program. Under the current locked plan (`spl-transfer-build` primary,
optional `token-risk-check` secondary — CONTEXT.md §4), neither needs this.
Don't implement speculatively ahead of that decision.
