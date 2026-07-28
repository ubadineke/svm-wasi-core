//! Account-state parsing for the Subscriptions & Allowances program's
//! `SubscriptionAuthority` and `RecurringDelegation` PDAs — the read side
//! complementing [`crate::instruction::subscriptions`]' encode side. Both
//! layouts are `#[repr(C, packed)]`, zero-copy on-chain structs (not borsh,
//! not TLV), verified against the real program's own state structs.

use crate::pubkey::Pubkey;

const DISCRIMINATOR_SUBSCRIPTION_AUTHORITY: u8 = 0;
const DISCRIMINATOR_RECURRING_DELEGATION: u8 = 3;

/// `SubscriptionAuthority`'s fixed on-chain size: `discriminator(1) +
/// user(32) + token_mint(32) + payer(32) + bump(1) + init_id(8)`.
pub const SUBSCRIPTION_AUTHORITY_LEN: usize = 106;

/// `RecurringDelegation`'s fixed on-chain size: a 107-byte shared `Header`
/// (`discriminator(1) + version(1) + bump(1) + delegator(32) +
/// delegatee(32) + payer(32) + init_id(8)`) followed by
/// `subscription_authority(32) + mint(32) + current_period_start_ts(8) +
/// period_length_s(8) + expiry_ts(8) + amount_per_period(8) +
/// amount_pulled_in_period(8)`. Matches the real program's own asserted
/// `RecurringDelegation::V1_LEN`.
pub const RECURRING_DELEGATION_LEN: usize = 211;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum SubscriptionStateError {
    #[error("account data is {actual} bytes, expected {expected} for a {kind}")]
    WrongLength {
        actual: usize,
        expected: usize,
        kind: &'static str,
    },
    #[error("expected discriminator {expected} for a {kind}, found {actual}")]
    WrongDiscriminator {
        actual: u8,
        expected: u8,
        kind: &'static str,
    },
}

/// A parsed `SubscriptionAuthority` account: the per-(user, mint) PDA the
/// program approves as the SPL Token delegate on the user's ATA, with
/// `u64::MAX` allowance. Its `init_id` is what every dependent delegation
/// pins itself to at creation time, so a delegation can detect a
/// stale/recreated authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubscriptionAuthority {
    pub user: Pubkey,
    pub token_mint: Pubkey,
    pub payer: Pubkey,
    pub bump: u8,
    pub init_id: i64,
}

impl SubscriptionAuthority {
    pub fn unpack(data: &[u8]) -> Result<Self, SubscriptionStateError> {
        if data.len() != SUBSCRIPTION_AUTHORITY_LEN {
            return Err(SubscriptionStateError::WrongLength {
                actual: data.len(),
                expected: SUBSCRIPTION_AUTHORITY_LEN,
                kind: "SubscriptionAuthority",
            });
        }
        if data[0] != DISCRIMINATOR_SUBSCRIPTION_AUTHORITY {
            return Err(SubscriptionStateError::WrongDiscriminator {
                actual: data[0],
                expected: DISCRIMINATOR_SUBSCRIPTION_AUTHORITY,
                kind: "SubscriptionAuthority",
            });
        }

        let mut user = [0u8; 32];
        user.copy_from_slice(&data[1..33]);
        let mut token_mint = [0u8; 32];
        token_mint.copy_from_slice(&data[33..65]);
        let mut payer = [0u8; 32];
        payer.copy_from_slice(&data[65..97]);
        let bump = data[97];
        let init_id = i64::from_le_bytes(data[98..106].try_into().unwrap());

        Ok(Self {
            user: Pubkey::new_from_array(user),
            token_mint: Pubkey::new_from_array(token_mint),
            payer: Pubkey::new_from_array(payer),
            bump,
            init_id,
        })
    }
}

/// A parsed `RecurringDelegation` account: a periodic transfer allowance
/// granting `delegatee` up to `amount_per_period` every `period_length_s`
/// seconds. The period counter rolls forward automatically — skipped
/// periods do not accumulate allowance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RecurringDelegation {
    pub delegator: Pubkey,
    pub delegatee: Pubkey,
    pub payer: Pubkey,
    pub init_id: i64,
    pub subscription_authority: Pubkey,
    pub mint: Pubkey,
    pub current_period_start_ts: i64,
    pub period_length_s: u64,
    pub expiry_ts: i64,
    pub amount_per_period: u64,
    pub amount_pulled_in_period: u64,
}

impl RecurringDelegation {
    pub fn unpack(data: &[u8]) -> Result<Self, SubscriptionStateError> {
        if data.len() != RECURRING_DELEGATION_LEN {
            return Err(SubscriptionStateError::WrongLength {
                actual: data.len(),
                expected: RECURRING_DELEGATION_LEN,
                kind: "RecurringDelegation",
            });
        }
        if data[0] != DISCRIMINATOR_RECURRING_DELEGATION {
            return Err(SubscriptionStateError::WrongDiscriminator {
                actual: data[0],
                expected: DISCRIMINATOR_RECURRING_DELEGATION,
                kind: "RecurringDelegation",
            });
        }

        let mut delegator = [0u8; 32];
        delegator.copy_from_slice(&data[3..35]);
        let mut delegatee = [0u8; 32];
        delegatee.copy_from_slice(&data[35..67]);
        let mut payer = [0u8; 32];
        payer.copy_from_slice(&data[67..99]);
        let init_id = i64::from_le_bytes(data[99..107].try_into().unwrap());

        let mut subscription_authority = [0u8; 32];
        subscription_authority.copy_from_slice(&data[107..139]);
        let mut mint = [0u8; 32];
        mint.copy_from_slice(&data[139..171]);
        let current_period_start_ts = i64::from_le_bytes(data[171..179].try_into().unwrap());
        let period_length_s = u64::from_le_bytes(data[179..187].try_into().unwrap());
        let expiry_ts = i64::from_le_bytes(data[187..195].try_into().unwrap());
        let amount_per_period = u64::from_le_bytes(data[195..203].try_into().unwrap());
        let amount_pulled_in_period = u64::from_le_bytes(data[203..211].try_into().unwrap());

        Ok(Self {
            delegator: Pubkey::new_from_array(delegator),
            delegatee: Pubkey::new_from_array(delegatee),
            payer: Pubkey::new_from_array(payer),
            init_id,
            subscription_authority: Pubkey::new_from_array(subscription_authority),
            mint: Pubkey::new_from_array(mint),
            current_period_start_ts,
            period_length_s,
            expiry_ts,
            amount_per_period,
            amount_pulled_in_period,
        })
    }

    /// Whether `current_unix_time` is at/after this delegation's expiry
    /// (`0` = never expires).
    pub fn is_expired(&self, current_unix_time: i64) -> bool {
        self.expiry_ts != 0 && current_unix_time >= self.expiry_ts
    }

    /// How much is available to pull right now: a fresh `amount_per_period`
    /// once the period has elapsed, otherwise whatever remains after
    /// `amount_pulled_in_period`. Always `0` past `expiry_ts`. A courtesy
    /// calculation — the runtime independently re-checks this on-chain.
    pub fn amount_available(&self, current_unix_time: i64) -> u64 {
        if self.is_expired(current_unix_time) {
            return 0;
        }
        let period_elapsed = current_unix_time
            >= self
                .current_period_start_ts
                .saturating_add(self.period_length_s as i64);
        if period_elapsed {
            self.amount_per_period
        } else {
            self.amount_per_period
                .saturating_sub(self.amount_pulled_in_period)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> Pubkey {
        Pubkey::new_from_array([byte; 32])
    }

    fn hand_assembled_subscription_authority(
        user: Pubkey,
        token_mint: Pubkey,
        payer: Pubkey,
        bump: u8,
        init_id: i64,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(SUBSCRIPTION_AUTHORITY_LEN);
        data.push(DISCRIMINATOR_SUBSCRIPTION_AUTHORITY);
        data.extend_from_slice(user.as_ref());
        data.extend_from_slice(token_mint.as_ref());
        data.extend_from_slice(payer.as_ref());
        data.push(bump);
        data.extend_from_slice(&init_id.to_le_bytes());
        assert_eq!(data.len(), SUBSCRIPTION_AUTHORITY_LEN);
        data
    }

    #[allow(clippy::too_many_arguments)]
    fn hand_assembled_recurring_delegation(
        delegator: Pubkey,
        delegatee: Pubkey,
        payer: Pubkey,
        init_id: i64,
        subscription_authority: Pubkey,
        mint: Pubkey,
        current_period_start_ts: i64,
        period_length_s: u64,
        expiry_ts: i64,
        amount_per_period: u64,
        amount_pulled_in_period: u64,
    ) -> Vec<u8> {
        let mut data = Vec::with_capacity(RECURRING_DELEGATION_LEN);
        data.push(DISCRIMINATOR_RECURRING_DELEGATION); // discriminator
        data.push(1); // version
        data.push(7); // bump
        data.extend_from_slice(delegator.as_ref());
        data.extend_from_slice(delegatee.as_ref());
        data.extend_from_slice(payer.as_ref());
        data.extend_from_slice(&init_id.to_le_bytes());
        data.extend_from_slice(subscription_authority.as_ref());
        data.extend_from_slice(mint.as_ref());
        data.extend_from_slice(&current_period_start_ts.to_le_bytes());
        data.extend_from_slice(&period_length_s.to_le_bytes());
        data.extend_from_slice(&expiry_ts.to_le_bytes());
        data.extend_from_slice(&amount_per_period.to_le_bytes());
        data.extend_from_slice(&amount_pulled_in_period.to_le_bytes());
        assert_eq!(data.len(), RECURRING_DELEGATION_LEN);
        data
    }

    #[test]
    fn unpacks_subscription_authority() {
        let user = pk(1);
        let mint = pk(2);
        let payer = pk(3);
        let data = hand_assembled_subscription_authority(user, mint, payer, 254, 12_345);

        let authority = SubscriptionAuthority::unpack(&data).unwrap();
        assert_eq!(authority.user, user);
        assert_eq!(authority.token_mint, mint);
        assert_eq!(authority.payer, payer);
        assert_eq!(authority.bump, 254);
        assert_eq!(authority.init_id, 12_345);
    }

    #[test]
    fn subscription_authority_rejects_wrong_length() {
        let err =
            SubscriptionAuthority::unpack(&[0u8; SUBSCRIPTION_AUTHORITY_LEN - 1]).unwrap_err();
        assert_eq!(
            err,
            SubscriptionStateError::WrongLength {
                actual: SUBSCRIPTION_AUTHORITY_LEN - 1,
                expected: SUBSCRIPTION_AUTHORITY_LEN,
                kind: "SubscriptionAuthority",
            }
        );
    }

    #[test]
    fn subscription_authority_rejects_wrong_discriminator() {
        let mut data = hand_assembled_subscription_authority(pk(1), pk(2), pk(3), 254, 0);
        data[0] = 3; // RecurringDelegation's discriminator, not SubscriptionAuthority's
        let err = SubscriptionAuthority::unpack(&data).unwrap_err();
        assert_eq!(
            err,
            SubscriptionStateError::WrongDiscriminator {
                actual: 3,
                expected: 0,
                kind: "SubscriptionAuthority"
            }
        );
    }

    #[test]
    fn unpacks_recurring_delegation() {
        let delegator = pk(1);
        let delegatee = pk(2);
        let payer = pk(3);
        let subscription_authority = pk(4);
        let mint = pk(5);
        let data = hand_assembled_recurring_delegation(
            delegator,
            delegatee,
            payer,
            99,
            subscription_authority,
            mint,
            1_000_000,
            2_592_000,
            0,
            15_000_000,
            5_000_000,
        );

        let delegation = RecurringDelegation::unpack(&data).unwrap();
        assert_eq!(delegation.delegator, delegator);
        assert_eq!(delegation.delegatee, delegatee);
        assert_eq!(delegation.payer, payer);
        assert_eq!(delegation.init_id, 99);
        assert_eq!(delegation.subscription_authority, subscription_authority);
        assert_eq!(delegation.mint, mint);
        assert_eq!(delegation.current_period_start_ts, 1_000_000);
        assert_eq!(delegation.period_length_s, 2_592_000);
        assert_eq!(delegation.expiry_ts, 0);
        assert_eq!(delegation.amount_per_period, 15_000_000);
        assert_eq!(delegation.amount_pulled_in_period, 5_000_000);
    }

    #[test]
    fn recurring_delegation_rejects_wrong_length() {
        let err = RecurringDelegation::unpack(&[0u8; RECURRING_DELEGATION_LEN - 1]).unwrap_err();
        assert_eq!(
            err,
            SubscriptionStateError::WrongLength {
                actual: RECURRING_DELEGATION_LEN - 1,
                expected: RECURRING_DELEGATION_LEN,
                kind: "RecurringDelegation",
            }
        );
    }

    #[test]
    fn recurring_delegation_rejects_wrong_discriminator() {
        let mut data = hand_assembled_recurring_delegation(
            pk(1),
            pk(2),
            pk(3),
            0,
            pk(4),
            pk(5),
            0,
            2_592_000,
            0,
            1,
            0,
        );
        data[0] = 0; // SubscriptionAuthority's discriminator, not RecurringDelegation's
        let err = RecurringDelegation::unpack(&data).unwrap_err();
        assert_eq!(
            err,
            SubscriptionStateError::WrongDiscriminator {
                actual: 0,
                expected: 3,
                kind: "RecurringDelegation"
            }
        );
    }

    #[test]
    fn full_amount_available_when_period_not_yet_pulled() {
        let data = hand_assembled_recurring_delegation(
            pk(1),
            pk(2),
            pk(3),
            0,
            pk(4),
            pk(5),
            1_000_000,
            2_592_000,
            0,
            15_000_000,
            0,
        );
        let delegation = RecurringDelegation::unpack(&data).unwrap();
        // Still within the current period (started at 1_000_000, lasts 2_592_000s).
        assert_eq!(delegation.amount_available(1_500_000), 15_000_000);
    }

    #[test]
    fn partial_amount_available_after_a_partial_pull() {
        let data = hand_assembled_recurring_delegation(
            pk(1),
            pk(2),
            pk(3),
            0,
            pk(4),
            pk(5),
            1_000_000,
            2_592_000,
            0,
            15_000_000,
            9_000_000,
        );
        let delegation = RecurringDelegation::unpack(&data).unwrap();
        assert_eq!(delegation.amount_available(1_500_000), 6_000_000);
    }

    #[test]
    fn full_amount_available_again_once_period_rolls_over() {
        let data = hand_assembled_recurring_delegation(
            pk(1),
            pk(2),
            pk(3),
            0,
            pk(4),
            pk(5),
            1_000_000,
            2_592_000,
            0,
            15_000_000,
            15_000_000, // fully pulled last period
        );
        let delegation = RecurringDelegation::unpack(&data).unwrap();
        // Well past current_period_start_ts + period_length_s -> fresh period.
        let next_period_time = 1_000_000 + 2_592_000 + 1;
        assert_eq!(delegation.amount_available(next_period_time), 15_000_000);
    }

    #[test]
    fn zero_available_once_expired() {
        let data = hand_assembled_recurring_delegation(
            pk(1),
            pk(2),
            pk(3),
            0,
            pk(4),
            pk(5),
            1_000_000,
            2_592_000,
            5_000_000,
            15_000_000,
            0,
        );
        let delegation = RecurringDelegation::unpack(&data).unwrap();
        assert!(delegation.is_expired(5_000_000));
        assert_eq!(delegation.amount_available(5_000_000), 0);
        assert_eq!(delegation.amount_available(6_000_000), 0);
    }

    #[test]
    fn never_expires_when_expiry_ts_is_zero() {
        let data = hand_assembled_recurring_delegation(
            pk(1),
            pk(2),
            pk(3),
            0,
            pk(4),
            pk(5),
            1_000_000,
            2_592_000,
            0,
            15_000_000,
            0,
        );
        let delegation = RecurringDelegation::unpack(&data).unwrap();
        assert!(!delegation.is_expired(i64::MAX - 1));
    }
}
