//! Solana Foundation's official Subscriptions & Allowances program:
//! delegated, capped, cyclical SPL Token transfers, audited (Cantina) and
//! live on mainnet. Only the "recurring delegation" model is encoded here —
//! not the fixed-allowance/merchant-plan variants, and not
//! revocation/cancellation.
//!
//! Hand-rolled: no published interface crate exists for this program.
//! Verified against its own source (`solana-program/subscriptions`). It's a
//! Pinocchio (not Anchor) program: instruction data is a raw
//! `#[repr(C, packed)]` struct dump behind a single discriminator byte.

use super::{known_id, system, AccountMeta, Instruction};
use crate::pubkey::Pubkey;

const INIT_SUBSCRIPTION_AUTHORITY_DISCRIMINATOR: u8 = 0;
const CREATE_RECURRING_DELEGATION_DISCRIMINATOR: u8 = 2;
const TRANSFER_RECURRING_DISCRIMINATOR: u8 = 5;

/// Sentinel for `create_recurring_delegation`'s
/// `expected_subscription_authority_init_id`, for bundling
/// [`initialize_subscription_authority`] and [`create_recurring_delegation`]
/// in the same transaction without predicting the real `init_id`. An
/// already-existing authority needs its real `init_id` passed instead.
pub const UNKNOWN_INIT_ID: i64 = i64::MIN;

pub fn id() -> Pubkey {
    known_id("De1egAFMkMWZSN5rYXRj9CAdheBamobVNubTsi9avR44")
}

/// `["SubscriptionAuthority", user, token_mint]` — one PDA per (user, mint)
/// pair. The program approves this PDA as the SPL/Token-2022 delegate on
/// the user's ATA with a `u64::MAX` allowance; the delegation PDAs (below)
/// are what actually cap what any delegatee can pull.
pub fn subscription_authority_pda(user: &Pubkey, token_mint: &Pubkey) -> Option<(Pubkey, u8)> {
    Pubkey::try_find_program_address(
        &[b"SubscriptionAuthority", user.as_ref(), token_mint.as_ref()],
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
) -> Option<(Pubkey, u8)> {
    Pubkey::try_find_program_address(
        &[
            b"delegation",
            subscription_authority.as_ref(),
            delegator.as_ref(),
            delegatee.as_ref(),
            &nonce.to_le_bytes(),
        ],
        &id(),
    )
}

/// The program's one fixed, canonical self-CPI event-logging PDA:
/// `["event_authority"]` — a single account per deployment, not per call.
pub fn event_authority_pda() -> Option<(Pubkey, u8)> {
    Pubkey::try_find_program_address(&[b"event_authority"], &id())
}

/// `InitSubscriptionAuthority` (discriminator 0, no args). Safe to include
/// unconditionally even if the authority already exists — account creation
/// is skipped, and re-approving the same `u64::MAX` allowance is a no-op.
/// `user` must sign.
pub fn initialize_subscription_authority(
    user: &Pubkey,
    token_mint: &Pubkey,
    user_ata: &Pubkey,
    token_program: &Pubkey,
) -> Option<Instruction> {
    let (subscription_authority, _bump) = subscription_authority_pda(user, token_mint)?;
    Some(Instruction {
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
/// optionally expiring at `expiry_ts` (`0` = never). `start_ts = 0` starts
/// the first period immediately; the on-chain program requires a non-zero
/// `expiry_ts` in that case (enforced on-chain, not re-validated here).
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
) -> Option<Instruction> {
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

    Some(Instruction {
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
/// sign; the runtime enforces the per-period cap on-chain regardless of
/// what `amount` is requested here.
///
/// Not handled: mints with an active Token-2022 transfer hook need extra
/// "remaining accounts" this builder doesn't provide.
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
) -> Option<Instruction> {
    let (subscription_authority, _bump) = subscription_authority_pda(delegator, token_mint)?;
    let (event_authority, _bump) = event_authority_pda()?;

    let mut data = Vec::with_capacity(1 + 72);
    data.push(TRANSFER_RECURRING_DISCRIMINATOR);
    data.extend_from_slice(&amount.to_le_bytes());
    data.extend_from_slice(delegator.as_ref());
    data.extend_from_slice(token_mint.as_ref());

    Some(Instruction {
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
        expected.extend_from_slice(delegator.as_ref());
        expected.extend_from_slice(mint.as_ref());
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
