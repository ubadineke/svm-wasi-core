//! Solana Foundation's official Subscriptions & Allowances program:
//! delegated, capped, cyclical SPL Token transfers, audited (Cantina) and
//! live on mainnet. Only the "recurring delegation" model is encoded here —
//! the minimum needed for an authorize + collect flow — not the fixed
//! allowance or merchant subscription-plan variants the real program also
//! supports, and not revocation/cancellation.
//!
//! Verified against the real program's own source (`solana-program/
//! subscriptions`), not the announcement or docs. This is a Pinocchio (not
//! Anchor) program: instruction data is a raw `#[repr(C, packed)]` struct
//! dump behind a single discriminator byte — not borsh, not bincode-tagged
//! like System, not TLV like Token-2022. A fourth distinct wire convention,
//! which is exactly why each program here gets verified independently.

use super::{known_id, system, AccountMeta, Instruction};
use crate::pubkey::{Pubkey, PubkeyError};

const INIT_SUBSCRIPTION_AUTHORITY_DISCRIMINATOR: u8 = 0;
const CREATE_RECURRING_DELEGATION_DISCRIMINATOR: u8 = 2;
const TRANSFER_RECURRING_DISCRIMINATOR: u8 = 5;

/// Sentinel for `create_recurring_delegation`'s
/// `expected_subscription_authority_init_id`: accepts a same-slot creation,
/// i.e. bundling [`initialize_subscription_authority`] and
/// [`create_recurring_delegation`] for a brand-new authority in one
/// transaction ("one-step signup") without needing to predict the `init_id`
/// `Clock::slot` will assign. Only valid when both instructions land in the
/// same transaction — an already-existing authority has a real, fixed
/// `init_id` that must be passed explicitly instead.
pub const UNKNOWN_INIT_ID: i64 = i64::MIN;

pub fn id() -> Pubkey {
    known_id("De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44")
}

/// `["SubscriptionAuthority", user, token_mint]` — one PDA per (user, mint)
/// pair. The program approves this PDA as the SPL/Token-2022 delegate on
/// the user's ATA with a `u64::MAX` allowance; individual delegation PDAs
/// (below) are what actually cap what any delegatee can pull. The
/// `u64::MAX` approval is not itself the safety boundary — it's inert
/// without a delegation authorizing a specific delegatee/amount/cadence.
pub fn subscription_authority_pda(
    user: &Pubkey,
    token_mint: &Pubkey,
) -> Result<(Pubkey, u8), PubkeyError> {
    Pubkey::find_program_address(
        &[
            b"SubscriptionAuthority",
            user.as_bytes(),
            token_mint.as_bytes(),
        ],
        &id(),
    )
}

/// `["delegation", subscription_authority, delegator, delegatee, nonce_le]`.
/// `nonce` disambiguates multiple concurrent delegations between the same
/// delegator/delegatee pair.
pub fn recurring_delegation_pda(
    subscription_authority: &Pubkey,
    delegator: &Pubkey,
    delegatee: &Pubkey,
    nonce: u64,
) -> Result<(Pubkey, u8), PubkeyError> {
    Pubkey::find_program_address(
        &[
            b"delegation",
            subscription_authority.as_bytes(),
            delegator.as_bytes(),
            delegatee.as_bytes(),
            &nonce.to_le_bytes(),
        ],
        &id(),
    )
}

/// The program's one fixed, canonical self-CPI event-logging PDA:
/// `["event_authority"]` — a single account per deployment, not per call.
pub fn event_authority_pda() -> Result<(Pubkey, u8), PubkeyError> {
    Pubkey::find_program_address(&[b"event_authority"], &id())
}

/// `InitSubscriptionAuthority` (discriminator 0, no instruction args beyond
/// the discriminator itself).
///
/// Safe to include unconditionally, every time, even if the authority
/// already exists: account creation is skipped when already initialized,
/// but the `Approve` CPI re-runs unconditionally regardless — re-approving
/// the same `u64::MAX` allowance is a no-op. That means a caller never
/// needs an extra RPC round trip to check existence first; just always
/// include this ahead of [`create_recurring_delegation`]. `user` must sign
/// (the `Approve` authority is the ATA owner, never a sponsor).
pub fn initialize_subscription_authority(
    user: &Pubkey,
    token_mint: &Pubkey,
    user_ata: &Pubkey,
    token_program: &Pubkey,
) -> Result<Instruction, PubkeyError> {
    let (subscription_authority, _bump) = subscription_authority_pda(user, token_mint)?;
    Ok(Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*user, true),
            AccountMeta::new(subscription_authority, false),
            AccountMeta::new_readonly(*token_mint, false),
            AccountMeta::new(*user_ata, false),
            AccountMeta::new_readonly(system::id(), false),
            AccountMeta::new_readonly(*token_program, false),
        ],
        data: vec![INIT_SUBSCRIPTION_AUTHORITY_DISCRIMINATOR],
    })
}

/// `CreateRecurringDelegation` (discriminator 2). Grants `delegatee` the
/// right to pull up to `amount_per_period` every `period_length_s` seconds,
/// optionally expiring at `expiry_ts` (`0` = never).
///
/// `start_ts = 0` starts the first period the moment this transaction
/// lands; the real program then requires a non-zero `expiry_ts`
/// specifically so a transaction held via durable nonce can't activate the
/// delegation unboundedly late (enforced on-chain in
/// `CreateRecurringDelegationData::validate` — this builder does not
/// re-validate that here, the runtime does).
///
/// The `subscription_authority` account must already exist — pair this with
/// [`initialize_subscription_authority`] in the same transaction.
#[allow(clippy::too_many_arguments)]
pub fn create_recurring_delegation(
    delegator: &Pubkey,
    delegatee: &Pubkey,
    token_mint: &Pubkey,
    nonce: u64,
    amount_per_period: u64,
    period_length_s: u64,
    start_ts: i64,
    expiry_ts: i64,
    expected_subscription_authority_init_id: i64,
) -> Result<Instruction, PubkeyError> {
    let (subscription_authority, _bump) = subscription_authority_pda(delegator, token_mint)?;
    let (delegation_account, _bump) =
        recurring_delegation_pda(&subscription_authority, delegator, delegatee, nonce)?;

    let mut data = Vec::with_capacity(1 + 48);
    data.push(CREATE_RECURRING_DELEGATION_DISCRIMINATOR);
    data.extend_from_slice(&nonce.to_le_bytes());
    data.extend_from_slice(&amount_per_period.to_le_bytes());
    data.extend_from_slice(&period_length_s.to_le_bytes());
    data.extend_from_slice(&start_ts.to_le_bytes());
    data.extend_from_slice(&expiry_ts.to_le_bytes());
    data.extend_from_slice(&expected_subscription_authority_init_id.to_le_bytes());

    Ok(Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*delegator, true),
            AccountMeta::new_readonly(subscription_authority, false),
            AccountMeta::new(delegation_account, false),
            AccountMeta::new_readonly(*delegatee, false),
            AccountMeta::new_readonly(system::id(), false),
        ],
        data,
    })
}

/// `TransferRecurring` (discriminator 5) — the "pull". `delegatee` must
/// sign; the runtime independently re-derives the per-period cap from the
/// delegation PDA's own on-chain state before moving anything, so this
/// instruction failing closed does not depend on the caller (or an LLM
/// deciding what to pass here) having computed the right amount — a wrong
/// or malicious `amount` simply gets rejected on-chain, it never silently
/// succeeds for more than the account's own stored state allows.
///
/// Scope note: mints with an active Token-2022 transfer hook need
/// additional "remaining accounts" the real program forwards to the hook
/// CPI. Not handled here — this builder targets plain SPL Token/Token-2022
/// mints without a transfer hook.
#[allow(clippy::too_many_arguments)]
pub fn transfer_recurring(
    delegation_account: &Pubkey,
    delegator: &Pubkey,
    delegatee: &Pubkey,
    token_mint: &Pubkey,
    delegator_ata: &Pubkey,
    receiver_ata: &Pubkey,
    token_program: &Pubkey,
    amount: u64,
) -> Result<Instruction, PubkeyError> {
    let (subscription_authority, _bump) = subscription_authority_pda(delegator, token_mint)?;
    let (event_authority, _bump) = event_authority_pda()?;

    let mut data = Vec::with_capacity(1 + 72);
    data.push(TRANSFER_RECURRING_DISCRIMINATOR);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(delegator.as_bytes());
    data.extend_from_slice(token_mint.as_bytes());

    Ok(Instruction {
        program_id: id(),
        accounts: vec![
            AccountMeta::new(*delegation_account, false),
            AccountMeta::new_readonly(subscription_authority, false),
            AccountMeta::new(*delegator_ata, false),
            AccountMeta::new(*receiver_ata, false),
            AccountMeta::new_readonly(*token_mint, false),
            AccountMeta::new_readonly(*token_program, false),
            AccountMeta::new_readonly(*delegatee, true),
            AccountMeta::new_readonly(event_authority, false),
            AccountMeta::new_readonly(id(), false),
        ],
        data,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::instruction::token;

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    #[test]
    fn program_id_matches_deployed_address() {
        assert_eq!(
            id().to_string(),
            "De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44"
        );
    }

    #[test]
    fn initialize_subscription_authority_encodes_bare_discriminator() {
        let user = pk(1);
        let mint = pk(2);
        let ata = pk(3);
        let token_program = token::token_program_id();

        let ix = initialize_subscription_authority(&user, &mint, &ata, &token_program).unwrap();

        assert_eq!(ix.program_id, id());
        assert_eq!(ix.data, vec![0]);
        let (expected_authority, _) = subscription_authority_pda(&user, &mint).unwrap();
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(user, true),
                AccountMeta::new(expected_authority, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new(ata, false),
                AccountMeta::new_readonly(system::id(), false),
                AccountMeta::new_readonly(token_program, false),
            ]
        );
    }

    #[test]
    fn create_recurring_delegation_encodes_fields_in_order() {
        let delegator = pk(1);
        let delegatee = pk(4);
        let mint = pk(2);

        let ix = create_recurring_delegation(
            &delegator,
            &delegatee,
            &mint,
            7,
            15_000_000,
            2_592_000,
            0,
            5_000_000_000,
            42,
        )
        .unwrap();

        assert_eq!(ix.program_id, id());
        let mut expected = vec![2u8];
        expected.extend_from_slice(&7u64.to_le_bytes());
        expected.extend_from_slice(&15_000_000u64.to_le_bytes());
        expected.extend_from_slice(&2_592_000u64.to_le_bytes());
        expected.extend_from_slice(&0i64.to_le_bytes());
        expected.extend_from_slice(&5_000_000_000i64.to_le_bytes());
        expected.extend_from_slice(&42i64.to_le_bytes());
        assert_eq!(ix.data, expected);
        assert_eq!(ix.data.len(), 1 + 48);

        let (subscription_authority, _) = subscription_authority_pda(&delegator, &mint).unwrap();
        let (delegation_account, _) =
            recurring_delegation_pda(&subscription_authority, &delegator, &delegatee, 7).unwrap();
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(delegator, true),
                AccountMeta::new_readonly(subscription_authority, false),
                AccountMeta::new(delegation_account, false),
                AccountMeta::new_readonly(delegatee, false),
                AccountMeta::new_readonly(system::id(), false),
            ]
        );
    }

    #[test]
    fn transfer_recurring_encodes_amount_delegator_mint_in_order() {
        let delegation_account = pk(9);
        let delegator = pk(1);
        let delegatee = pk(4);
        let mint = pk(2);
        let delegator_ata = pk(5);
        let receiver_ata = pk(6);
        let token_program = token::token_program_id();

        let ix = transfer_recurring(
            &delegation_account,
            &delegator,
            &delegatee,
            &mint,
            &delegator_ata,
            &receiver_ata,
            &token_program,
            250_000,
        )
        .unwrap();

        let mut expected = vec![5u8];
        expected.extend_from_slice(&250_000u64.to_le_bytes());
        expected.extend_from_slice(delegator.as_bytes());
        expected.extend_from_slice(mint.as_bytes());
        assert_eq!(ix.data, expected);
        assert_eq!(ix.data.len(), 1 + 72);

        let (subscription_authority, _) = subscription_authority_pda(&delegator, &mint).unwrap();
        let (event_authority, _) = event_authority_pda().unwrap();
        assert_eq!(
            ix.accounts,
            vec![
                AccountMeta::new(delegation_account, false),
                AccountMeta::new_readonly(subscription_authority, false),
                AccountMeta::new(delegator_ata, false),
                AccountMeta::new(receiver_ata, false),
                AccountMeta::new_readonly(mint, false),
                AccountMeta::new_readonly(token_program, false),
                AccountMeta::new_readonly(delegatee, true),
                AccountMeta::new_readonly(event_authority, false),
                AccountMeta::new_readonly(id(), false),
            ]
        );
    }

    #[test]
    fn event_authority_pda_is_deterministic() {
        // Fixed single seed, no per-call arguments -> same value every time.
        let (a, bump_a) = event_authority_pda().unwrap();
        let (b, bump_b) = event_authority_pda().unwrap();
        assert_eq!(a, b);
        assert_eq!(bump_a, bump_b);
    }
}
