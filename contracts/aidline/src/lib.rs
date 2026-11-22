#![no_std]

//! Aidline: milestone based escrow for disaster relief and climate campaigns.
//!
//! Donations are held by the contract and only reach the beneficiary one
//! milestone at a time, after the campaign's verifier confirms the work was
//! done. If a campaign is cancelled or runs out of time, donors can reclaim
//! their share of whatever has not been released yet.

mod errors;
mod events;
mod storage;
mod types;

#[cfg(test)]
mod test;

use soroban_sdk::{
    Address, BytesN, ContractExecutable, Env, String, Vec, contract, contractimpl, token,
};

pub use errors::Error;
pub use types::{
    BondStatus, Campaign, CampaignKind, CampaignStatus, Pledge, SponsorPool, VerifierBond,
};

use events::{
    AdminAccepted, AdminChanged, AdminProposed, BondSlashed, BondWithdrawn, CampaignCancelled,
    CampaignCreated, ContractPaused, ContractUnpaused, ContractUpgraded, DeadlineExtended, Donated,
    EmergencyAdvanceReleased, MatchingApplied, MetadataUpdated, MilestoneApproved,
    MilestoneRejected, MilestoneReleased, PlatformFeeUpdated, PledgeCancelled, PledgeCreated,
    PledgePulled, PledgeSettlement, PledgeSkipped, Refunded, SponsorPoolDeposited,
    SponsorPoolReturned, TokenAllowlistUpdated, TreasuryUpdated, VerifierBondPosted,
    VerifierDeregistered, VerifierReassigned, VerifierUpdated,
};

const MAX_MILESTONES: u32 = 20;
/// Maximum length in bytes for metadata and proof URIs.
const MAX_URI_LENGTH: u32 = 256;
/// Maximum matching ratio (100 % = 10 000 bps).
const MAX_RATIO_BPS: u32 = 10_000;
/// Maximum platform fee in basis points (200 bps = 2.00%).
const MAX_PLATFORM_FEE_BPS: u32 = 200;
/// Reason code emitted in PledgeSkipped when the donor has no allowance.
const SKIP_REASON_NO_ALLOWANCE: u32 = 1;
/// Reason code emitted in PledgeSkipped when the pledge is fully consumed.
const SKIP_REASON_EXHAUSTED: u32 = 2;

/// Maximum duration (in seconds) for a one-time deadline extension (30 days).
const MAX_DEADLINE_EXTENSION: u64 = 30 * 86_400;

/// Maximum number of times a campaign's verifier may be reassigned.
pub const MAX_VERIFIER_REASSIGNMENTS: u32 = 2;

/// The emergency advance is capped at 20% of the campaign goal (200 bps out of
/// 1000, or equivalently goal / 5).  Integer arithmetic: advance = goal / 5
/// (rounds down, so the cap is never exceeded).
const EMERGENCY_ADVANCE_BPS: i128 = 2_000; // 20% in basis points
const BPS_DENOM: i128 = 10_000;

#[contract]
pub struct Aidline;

#[contractimpl]
impl Aidline {
    /// Initialises the contract, storing the `admin` address and the `token`
    /// (a Stellar Asset Contract such as USDC) used for all campaigns.
    ///
    /// Called once at deployment time; may not be called again.
    ///
    /// # Errors
    /// This function does not return errors; panics if storage is unavailable.
    pub fn __constructor(env: Env, admin: Address, token: Address) {
        storage::set_admin(&env, &admin);
        storage::set_token(&env, &token);
        storage::set_token_allowed(&env, &token, true);
        storage::bump_instance(&env);
    }

    // ─── Admin ────────────────────────────────────────────────────────────────

    /// Registers `verifier` as an active verifier.
    ///
    /// Only the admin may call this function. Emits [`VerifierUpdated`] with
    /// `active = true`.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin (enforced via
    ///   `require_auth` on the stored admin address).
    pub fn add_verifier(env: Env, verifier: Address) {
        storage::admin(&env).require_auth();
        storage::set_verifier(&env, &verifier, true);
        VerifierUpdated {
            verifier,
            active: true,
        }
        .publish(&env);
    }

    /// Deactivates `verifier`, preventing them from approving future milestones.
    ///
    /// Only the admin may call this function. Campaigns previously assigned to
    /// the verifier will freeze until the campaign is cancelled or reassigned
    /// via [`reassign_verifier`]. Emits [`VerifierUpdated`] with `active = false`.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin (enforced via
    ///   `require_auth` on the stored admin address).
    pub fn remove_verifier(env: Env, verifier: Address) {
        storage::admin(&env).require_auth();
        storage::set_verifier(&env, &verifier, false);
        VerifierUpdated {
            verifier,
            active: false,
        }
        .publish(&env);
    }

    /// Transfers admin control to `new_admin`.
    ///
    /// Only the current admin may call this. Emits [`AdminChanged`] with
    /// both the old and new admin addresses so indexers can track the change.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the current admin (enforced
    ///   via `require_auth` on the stored admin address).
    pub fn set_admin(env: Env, new_admin: Address) {
        let old_admin = storage::admin(&env);
        old_admin.require_auth();
        storage::set_admin(&env, &new_admin);
        storage::remove_pending_admin(&env);
        AdminChanged {
            old: old_admin,
            new: new_admin,
        }
        .publish(&env);
    }

    /// Proposes transferring admin control to `new_admin`.
    ///
    /// Only the current admin may call this. The transfer is not finalized
    /// until `new_admin` calls [`accept_admin`]. Calling this again replaces
    /// any existing pending proposal. Emits [`AdminProposed`].
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the current admin.
    pub fn propose_admin(env: Env, new_admin: Address) {
        let current_admin = storage::admin(&env);
        current_admin.require_auth();
        storage::set_pending_admin(&env, &new_admin);
        AdminProposed {
            current_admin,
            pending_admin: new_admin,
        }
        .publish(&env);
    }

    /// Finalizes a pending admin transfer.
    ///
    /// Must be called with authorization from the pending admin set via
    /// [`propose_admin`]. Updates the stored admin, clears the pending proposal,
    /// and emits [`AdminAccepted`] and [`AdminChanged`].
    ///
    /// # Errors
    /// - [`Error::NoPendingAdmin`]: no admin transfer proposal is currently pending.
    /// - [`Error::Unauthorized`]: caller is not the pending admin.
    pub fn accept_admin(env: Env) -> Result<(), Error> {
        let pending = storage::pending_admin(&env).ok_or(Error::NoPendingAdmin)?;
        pending.require_auth();
        let old_admin = storage::admin(&env);
        storage::set_admin(&env, &pending);
        storage::remove_pending_admin(&env);

        AdminAccepted {
            old_admin: old_admin.clone(),
            new_admin: pending.clone(),
        }
        .publish(&env);

        AdminChanged {
            old: old_admin,
            new: pending,
        }
        .publish(&env);

        Ok(())
    }

    /// Pauses the contract in emergencies.
    ///
    /// Only the admin may call this. While paused, `donate`, `approve_milestone`,
    /// `create_campaign`, and `emergency_fast_track` fail with [`Error::Paused`].
    /// Refunds keep working so donors are never locked in. Emits [`ContractPaused`].
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin.
    pub fn pause(env: Env) {
        let admin = storage::admin(&env);
        admin.require_auth();
        storage::set_paused(&env, true);
        ContractPaused { admin }.publish(&env);
    }

    /// Unpauses the contract, restoring normal operation.
    ///
    /// Only the admin may call this. Emits [`ContractUnpaused`].
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin.
    pub fn unpause(env: Env) {
        let admin = storage::admin(&env);
        admin.require_auth();
        storage::set_paused(&env, false);
        ContractUnpaused { admin }.publish(&env);
    }

    /// Upgrades the contract's Wasm executable to `new_wasm_hash`.
    ///
    /// Only the current admin may call this. The new Wasm code must already
    /// be installed on-chain. Emits [`ContractUpgraded`].
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin.
    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin = storage::admin(&env);
        admin.require_auth();
        env.deployer()
            .update_current_contract(ContractExecutable::Wasm(new_wasm_hash.clone()));
        ContractUpgraded { new_wasm_hash }.publish(&env);
    }

    // ─── Platform Fee and Treasury (admin only) ───────────────────────────────

    /// Sets the platform fee in basis points.
    ///
    /// Only the admin may call this. The fee is capped at 200 basis points (2.00%).
    /// Setting `fee_bps` to `0` disables the platform fee (default).
    /// Emits [`PlatformFeeUpdated`].
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin.
    /// - [`Error::InvalidAmount`]: `fee_bps` exceeds 200 basis points.
    pub fn set_platform_fee(env: Env, fee_bps: u32) -> Result<(), Error> {
        storage::admin(&env).require_auth();
        if fee_bps > MAX_PLATFORM_FEE_BPS {
            return Err(Error::InvalidAmount);
        }
        storage::set_platform_fee(&env, fee_bps);
        PlatformFeeUpdated { fee_bps }.publish(&env);
        Ok(())
    }

    /// Sets the platform treasury address that receives milestone release fees.
    ///
    /// Only the admin may call this. Emits [`TreasuryUpdated`].
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin.
    pub fn set_treasury(env: Env, treasury: Address) {
        storage::admin(&env).require_auth();
        storage::set_treasury(&env, &treasury);
        TreasuryUpdated { treasury }.publish(&env);
    }

    // ─── Token Allowlist (admin only) ─────────────────────────────────────────

    /// Adds `token` to the list of allowed campaign tokens.
    ///
    /// Only the admin may call this. Emits [`TokenAllowlistUpdated`].
    pub fn add_allowed_token(env: Env, token: Address) {
        storage::admin(&env).require_auth();
        storage::set_token_allowed(&env, &token, true);
        TokenAllowlistUpdated {
            token,
            allowed: true,
        }
        .publish(&env);
    }

    /// Removes `token` from the list of allowed campaign tokens.
    ///
    /// Only the admin may call this. Emits [`TokenAllowlistUpdated`].
    pub fn remove_allowed_token(env: Env, token: Address) {
        storage::admin(&env).require_auth();
        storage::set_token_allowed(&env, &token, false);
        TokenAllowlistUpdated {
            token,
            allowed: false,
        }
        .publish(&env);
    }

    /// Returns `true` if `token` is currently on the allowlist for new campaigns.
    pub fn is_token_allowed(env: Env, token: Address) -> bool {
        storage::is_token_allowed(&env, &token)
    }

    // ─── Bond configuration (admin only) ──────────────────────────────────────

    /// Sets the minimum bond amount a verifier must post when calling
    /// [`register_with_bond`].
    ///
    /// Only the admin may call this. Setting `amount` to `0` disables the bond
    /// requirement.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin.
    /// - [`Error::InvalidAmount`]: `amount` is negative.
    pub fn set_bond_requirement(env: Env, amount: i128) -> Result<(), Error> {
        storage::admin(&env).require_auth();
        if amount < 0 {
            return Err(Error::InvalidAmount);
        }
        storage::set_bond_requirement(&env, amount);
        Ok(())
    }

    /// Sets the delay (in seconds) a verifier must wait after deregistering
    /// before they can withdraw their bond.
    ///
    /// Only the admin may call this. A non-zero delay gives the admin time to
    /// slash a fraudulent verifier before they can withdraw funds.
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin.
    pub fn set_bond_withdraw_delay(env: Env, delay: u64) {
        storage::admin(&env).require_auth();
        storage::set_bond_withdraw_delay(&env, delay);
    }

    // ─── Bonded verifier registration ─────────────────────────────────────────

    /// Registers `verifier` and transfers their bond into escrow.
    ///
    /// The caller must be `verifier` (auth enforced). `bond_amount` must be at
    /// least the value returned by [`bond_requirement`] and must be > 0. The
    /// tokens are transferred from `verifier` to the contract immediately.
    /// Emits [`VerifierBondPosted`].
    ///
    /// # Errors
    /// - [`Error::BondRequired`]: `bond_amount` is below the required minimum
    ///   or is zero.
    /// - [`Error::Unauthorized`]: `verifier` is already registered.
    pub fn register_with_bond(env: Env, verifier: Address, bond_amount: i128) -> Result<(), Error> {
        verifier.require_auth();

        let required = storage::bond_requirement(&env);
        if bond_amount < required || bond_amount <= 0 {
            return Err(Error::BondRequired);
        }

        if storage::is_verifier(&env, &verifier) {
            return Err(Error::Unauthorized);
        }

        token::Client::new(&env, &storage::token(&env)).transfer(
            &verifier,
            env.current_contract_address(),
            &bond_amount,
        );

        let bond = VerifierBond {
            verifier: verifier.clone(),
            amount: bond_amount,
            remaining: bond_amount,
            status: BondStatus::Active,
            deregistered_at: 0,
        };
        storage::save_verifier_bond(&env, &bond);
        storage::set_verifier(&env, &verifier, true);

        VerifierBondPosted {
            verifier,
            amount: bond_amount,
        }
        .publish(&env);

        Ok(())
    }

    /// Deregisters `verifier`, beginning the bond withdrawal delay countdown.
    ///
    /// Either the verifier themselves or the admin may call this. The verifier
    /// is removed from the active registry immediately, but their bond enters
    /// `PendingWithdrawal` status and cannot be withdrawn until the delay set
    /// by [`set_bond_withdraw_delay`] has elapsed. Emits [`VerifierDeregistered`].
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: `caller` is neither `verifier` nor the admin.
    /// - [`Error::NotVerifier`]: `verifier` is not currently registered.
    pub fn deregister_verifier(env: Env, caller: Address, verifier: Address) -> Result<(), Error> {
        caller.require_auth();
        let admin = storage::admin(&env);
        if caller != verifier && caller != admin {
            return Err(Error::Unauthorized);
        }

        if !storage::is_verifier(&env, &verifier) {
            return Err(Error::NotVerifier);
        }

        storage::set_verifier(&env, &verifier, false);

        let now = env.ledger().timestamp();

        if let Some(mut bond) = storage::verifier_bond(&env, &verifier) {
            bond.status = BondStatus::PendingWithdrawal;
            bond.deregistered_at = now;
            storage::save_verifier_bond(&env, &bond);
        }

        VerifierDeregistered {
            verifier,
            deregistered_at: now,
        }
        .publish(&env);

        Ok(())
    }

    /// Withdraws the verifier's remaining bond back to their wallet.
    ///
    /// Requires auth from `verifier`. The bond must be in `PendingWithdrawal`
    /// status and the withdrawal delay must have elapsed since deregistration.
    /// Emits [`BondWithdrawn`] and returns the amount transferred.
    ///
    /// # Errors
    /// - [`Error::BondNotFound`]: no bond record exists for `verifier`.
    /// - [`Error::BondNotWithdrawable`]: bond is not in `PendingWithdrawal`
    ///   status, or the remaining amount is zero.
    /// - [`Error::WithdrawDelayNotMet`]: the required delay since
    ///   deregistration has not yet elapsed.
    pub fn withdraw_bond(env: Env, verifier: Address) -> Result<i128, Error> {
        verifier.require_auth();

        let mut bond = storage::verifier_bond(&env, &verifier).ok_or(Error::BondNotFound)?;

        if bond.status != BondStatus::PendingWithdrawal {
            return Err(Error::BondNotWithdrawable);
        }

        let delay = storage::bond_withdraw_delay(&env);
        let elapsed = env.ledger().timestamp().saturating_sub(bond.deregistered_at);
        if elapsed < delay {
            return Err(Error::WithdrawDelayNotMet);
        }

        let withdrawable = bond.remaining;
        if withdrawable <= 0 {
            return Err(Error::BondNotWithdrawable);
        }

        bond.remaining = 0;
        bond.status = BondStatus::Withdrawn;
        storage::save_verifier_bond(&env, &bond);

        token::Client::new(&env, &storage::token(&env)).transfer(
            &env.current_contract_address(),
            &verifier,
            &withdrawable,
        );

        BondWithdrawn {
            verifier,
            amount: withdrawable,
        }
        .publish(&env);

        Ok(withdrawable)
    }

    /// Slashes `slash_amount` from `verifier`'s bond and credits it to
    /// `campaign_id`'s raised total so it is distributed to donors on refund.
    ///
    /// Only the admin may call this. The slash amount must not exceed the
    /// verifier's remaining bond. Emits [`BondSlashed`].
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin.
    /// - [`Error::InvalidAmount`]: `slash_amount` is zero or negative.
    /// - [`Error::BondNotFound`]: no bond record exists for `verifier`.
    /// - [`Error::BondNotWithdrawable`]: bond has already been withdrawn.
    /// - [`Error::SlashExceedsBond`]: `slash_amount` exceeds remaining bond.
    pub fn slash_verifier(
        env: Env,
        verifier: Address,
        campaign_id: u64,
        slash_amount: i128,
    ) -> Result<(), Error> {
        storage::admin(&env).require_auth();

        if slash_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let mut bond = storage::verifier_bond(&env, &verifier).ok_or(Error::BondNotFound)?;

        if bond.status == BondStatus::Withdrawn {
            return Err(Error::BondNotWithdrawable);
        }
        if slash_amount > bond.remaining {
            return Err(Error::SlashExceedsBond);
        }

        bond.remaining -= slash_amount;
        if bond.remaining == 0 {
            bond.status = BondStatus::Slashed;
        }
        storage::save_verifier_bond(&env, &bond);

        let campaign_result = storage::campaign(&env, campaign_id);
        if let Ok(mut campaign) = campaign_result {
            let contract_addr = env.current_contract_address();
            let prev = storage::contribution(&env, campaign_id, &contract_addr);
            campaign.raised = campaign
                .raised
                .checked_add(slash_amount)
                .unwrap_or(campaign.raised);
            storage::save_campaign(&env, &campaign);
            storage::set_contribution(&env, campaign_id, &contract_addr, prev + slash_amount);
        }

        BondSlashed {
            verifier: verifier.clone(),
            campaign_id,
            slashed_amount: slash_amount,
        }
        .publish(&env);

        Ok(())
    }

    // ─── Bond views ───────────────────────────────────────────────────────────

    /// Returns the [`VerifierBond`] record for `verifier`, or `None` if no
    /// bond has ever been posted.
    pub fn get_verifier_bond(env: Env, verifier: Address) -> Option<VerifierBond> {
        storage::verifier_bond(&env, &verifier)
    }

    /// Returns the current required bond amount. `0` means no bond is required.
    pub fn bond_requirement(env: Env) -> i128 {
        storage::bond_requirement(&env)
    }

    /// Returns the bond withdrawal delay in seconds. `0` means no delay.
    pub fn bond_withdraw_delay(env: Env) -> u64 {
        storage::bond_withdraw_delay(&env)
    }

    // ─── Campaigns ────────────────────────────────────────────────────────────

    /// Creates a new campaign and returns its ID.
    ///
    /// `creator` must authorise the call. `verifier` must be a registered
    /// verifier. `token` must be on the admin approved allowlist.
    /// `deadline` must be in the future. `milestones` must be
    /// non-empty, have at most [`MAX_MILESTONES`] entries, and every entry
    /// must be positive. The campaign's `goal` is the sum of all milestones.
    /// Emits [`CampaignCreated`].
    ///
    /// # Errors
    /// - [`Error::UriTooLong`]: `metadata_uri` exceeds [`MAX_URI_LENGTH`] bytes.
    /// - [`Error::ConflictOfInterest`]: `verifier` is equal to `creator` or
    ///   `beneficiary`.
    /// - [`Error::NotVerifier`]: `verifier` is not currently registered.
    /// - [`Error::TokenNotAllowed`]: `token` is not on the admin allowlist.
    /// - [`Error::DeadlineInPast`]: `deadline` is not after the current
    ///   ledger timestamp.
    /// - [`Error::InvalidMilestones`]: `milestones` is empty, exceeds
    ///   [`MAX_MILESTONES`], contains a non-positive value, or the sum
    ///   overflows `i128`.
    pub fn create_campaign(
        env: Env,
        creator: Address,
        beneficiary: Address,
        verifier: Address,
        token: Address,
        kind: CampaignKind,
        metadata_uri: String,
        deadline: u64,
        milestones: Vec<i128>,
    ) -> Result<u64, Error> {
        let mut verifiers = Vec::new(&env);
        verifiers.push_back(verifier.clone());
        Self::create_multisig_campaign_inner(
            env,
            creator,
            beneficiary,
            verifiers,
            1,
            token,
            kind,
            metadata_uri,
            deadline,
            milestones,
            0,
        )
    }

    /// Creates a new campaign with a minimum donation floor.
    ///
    /// Donations below `min_donation` are rejected by [`donate`], except for
    /// the final donation that reaches or exceeds the remaining goal.
    /// A `min_donation` of 0 imposes no floor.
    ///
    /// # Errors
    /// - [`Error::InvalidAmount`]: `min_donation` is negative.
    /// - All other errors from [`create_campaign`].
    pub fn create_campaign_min_donation(
        env: Env,
        creator: Address,
        beneficiary: Address,
        verifier: Address,
        token: Address,
        kind: CampaignKind,
        metadata_uri: String,
        deadline: u64,
        milestones: Vec<i128>,
        min_donation: i128,
    ) -> Result<u64, Error> {
        let mut verifiers = Vec::new(&env);
        verifiers.push_back(verifier.clone());
        Self::create_multisig_campaign_inner(
            env,
            creator,
            beneficiary,
            verifiers,
            1,
            token,
            kind,
            metadata_uri,
            deadline,
            milestones,
            min_donation,
        )
    }

    /// Creates a new campaign with multiple verifiers, an approval threshold, and a token.
    ///
    /// `threshold` verifier approvals are required before any milestone can be
    /// released. `threshold` must be between 1 and `verifiers.len()` inclusive.
    /// Every entry in `verifiers` must be currently registered and distinct.
    /// `token` must be on the admin approved allowlist.
    ///
    /// # Errors
    /// - [`Error::TokenNotAllowed`]: `token` is not on the allowlist.
    /// - [`Error::InvalidThreshold`]: `threshold` is 0 or exceeds `verifiers.len()`.
    /// - [`Error::DuplicateVerifier`]: `verifiers` contains duplicate addresses.
    /// - [`Error::NotVerifier`]: an address in `verifiers` is not registered.
    /// - All other errors from [`create_campaign`].
    pub fn create_multisig_campaign(
        env: Env,
        creator: Address,
        beneficiary: Address,
        verifiers: Vec<Address>,
        threshold: u32,
        token: Address,
        kind: CampaignKind,
        metadata_uri: String,
        deadline: u64,
        milestones: Vec<i128>,
    ) -> Result<u64, Error> {
        Self::create_multisig_campaign_inner(
            env,
            creator,
            beneficiary,
            verifiers,
            threshold,
            token,
            kind,
            metadata_uri,
            deadline,
            milestones,
            0,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn create_multisig_campaign_inner(
        env: Env,
        creator: Address,
        beneficiary: Address,
        verifiers: Vec<Address>,
        threshold: u32,
        token: Address,
        kind: CampaignKind,
        metadata_uri: String,
        deadline: u64,
        milestones: Vec<i128>,
        min_donation: i128,
    ) -> Result<u64, Error> {
        creator.require_auth();
        storage::bump_instance(&env);

        if min_donation < 0 {
            return Err(Error::InvalidAmount);
        }
        if metadata_uri.len() > MAX_URI_LENGTH {
            return Err(Error::UriTooLong);
        }
        if verifiers.contains(&creator) || verifiers.contains(&beneficiary) {
            return Err(Error::ConflictOfInterest);
        }

        if storage::is_paused(&env) {
            return Err(Error::Paused);
        }

        if !storage::is_token_allowed(&env, &token) {
            return Err(Error::TokenNotAllowed);
        }

        if verifiers.is_empty() || threshold == 0 || threshold > verifiers.len() {
            return Err(Error::InvalidThreshold);
        }

        let mut seen = Vec::new(&env);
        for v in verifiers.iter() {
            if seen.contains(&v) {
                return Err(Error::DuplicateVerifier);
            }
            if !storage::is_verifier(&env, &v) {
                return Err(Error::NotVerifier);
            }
            seen.push_back(v);
        }

        if deadline <= env.ledger().timestamp() {
            return Err(Error::DeadlineInPast);
        }
        if milestones.is_empty() || milestones.len() > MAX_MILESTONES {
            return Err(Error::InvalidMilestones);
        }
        let mut goal: i128 = 0;
        for amount in milestones.iter() {
            if amount <= 0 {
                return Err(Error::InvalidMilestones);
            }
            goal = goal.checked_add(amount).ok_or(Error::InvalidMilestones)?;
        }

        let id = storage::next_campaign_id(&env);
        let primary_verifier = verifiers.get(0).unwrap();
        let campaign = Campaign {
            id,
            creator: creator.clone(),
            beneficiary,
            verifier: primary_verifier,
            token,
            kind,
            metadata_uri,
            goal,
            deadline,
            milestones,
            milestones_released: 0,
            raised: 0,
            released: 0,
            status: CampaignStatus::Active,
            emergency_advance: 0,
            verifiers,
            threshold,
            deadline_extended: false,
            min_donation,
            verifier_reassignments: 0,
        };
        storage::save_campaign(&env, &campaign);

        CampaignCreated {
            campaign_id: id,
            creator,
            kind,
            goal,
            deadline,
            min_donation,
        }
        .publish(&env);
        Ok(id)
    }

    /// Creates a campaign with per-milestone due dates.
    pub fn create_campaign_with_due_dates(
        env: Env,
        creator: Address,
        beneficiary: Address,
        verifier: Address,
        token: Address,
        kind: CampaignKind,
        metadata_uri: String,
        deadline: u64,
        milestones: Vec<i128>,
        milestone_due_dates: Vec<u64>,
    ) -> Result<u64, Error> {
        let id = Self::create_campaign(
            env.clone(),
            creator,
            beneficiary,
            verifier,
            token,
            kind,
            metadata_uri,
            deadline,
            milestones.clone(),
        )?;
        if milestone_due_dates.len() != milestones.len() {
            return Err(Error::InvalidMilestones);
        }
        storage::set_milestone_due_dates(&env, id, &milestone_due_dates);
        Ok(id)
    }

    /// Updates the off-chain metadata URI for `campaign_id`.
    ///
    /// Only the campaign's creator may call this, and only before any
    /// donations have been received (`raised == 0`). Emits [`MetadataUpdated`].
    ///
    /// # Errors
    /// - [`Error::UriTooLong`]: `new_metadata_uri` exceeds [`MAX_URI_LENGTH`] bytes.
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::CampaignNotActive`]: campaign is not currently active.
    /// - [`Error::CampaignExpired`]: campaign deadline has passed.
    /// - [`Error::DonationsAlreadyStarted`]: campaign has already received donations.
    pub fn update_metadata(
        env: Env,
        campaign_id: u64,
        new_metadata_uri: String,
    ) -> Result<(), Error> {
        let mut campaign = storage::campaign(&env, campaign_id)?;
        campaign.creator.require_auth();
        Self::ensure_open(&env, &campaign)?;

        if new_metadata_uri.len() > MAX_URI_LENGTH {
            return Err(Error::UriTooLong);
        }

        if campaign.raised > 0 {
            return Err(Error::DonationsAlreadyStarted);
        }

        campaign.metadata_uri = new_metadata_uri.clone();
        storage::save_campaign(&env, &campaign);

        MetadataUpdated {
            campaign_id,
            new_metadata_uri,
        }
        .publish(&env);

        Ok(())
    }

    /// Extends an active campaign's deadline by up to 30 days.
    ///
    /// Only the campaign's creator may call this. An extension can be
    /// granted at most once per campaign, and only while the campaign is
    /// active and before the current deadline has elapsed. Emits
    /// [`DeadlineExtended`].
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::CampaignNotActive`]: campaign is not in `Active` status.
    /// - [`Error::CampaignExpired`]: current deadline has already elapsed.
    /// - [`Error::DeadlineAlreadyExtended`]: campaign has already used its
    ///   one-time extension.
    /// - [`Error::InvalidDeadlineExtension`]: `new_deadline` is not after the
    ///   current deadline or extends it by more than 30 days.
    pub fn extend_deadline(env: Env, campaign_id: u64, new_deadline: u64) -> Result<(), Error> {
        let mut campaign = storage::campaign(&env, campaign_id)?;
        campaign.creator.require_auth();
        Self::ensure_open(&env, &campaign)?;

        if campaign.deadline_extended {
            return Err(Error::DeadlineAlreadyExtended);
        }

        if new_deadline <= campaign.deadline
            || new_deadline > campaign.deadline + MAX_DEADLINE_EXTENSION
        {
            return Err(Error::InvalidDeadlineExtension);
        }

        let old_deadline = campaign.deadline;
        campaign.deadline = new_deadline;
        campaign.deadline_extended = true;
        storage::save_campaign(&env, &campaign);

        DeadlineExtended {
            campaign_id,
            old_deadline,
            new_deadline,
        }
        .publish(&env);

        Ok(())
    }

    /// Donates `amount` tokens from `donor` to `campaign_id`.
    ///
    /// Accepts up to the remaining amount needed to reach the campaign goal
    /// (`min(amount, goal - raised)`). Only that accepted amount is transferred
    /// into escrow, and the accepted amount is returned.
    ///
    /// The campaign must be active and not expired. If the campaign is already
    /// fully funded (`raised >= goal`), the call fails with [`Error::GoalExceeded`].
    /// Emits [`Donated`] with the accepted amount.
    ///
    /// # Errors
    /// - [`Error::InvalidAmount`]: `amount` is zero or negative.
    /// - [`Error::DonationBelowMinimum`]: `amount` is below the campaign's
    ///   `min_donation` and does not reach the remaining goal.
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::CampaignNotActive`]: campaign is not in `Active` status.
    /// - [`Error::CampaignExpired`]: campaign deadline has passed.
    /// - [`Error::GoalExceeded`]: campaign is already fully funded.
    pub fn donate(env: Env, donor: Address, campaign_id: u64, amount: i128) -> Result<i128, Error> {
        donor.require_auth();
        if storage::is_paused(&env) {
            return Err(Error::Paused);
        }
        if amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let mut campaign = storage::campaign(&env, campaign_id)?;
        Self::ensure_open(&env, &campaign)?;

        if campaign.raised >= campaign.goal {
            return Err(Error::GoalExceeded);
        }

        let remaining = campaign.goal - campaign.raised;
        if campaign.min_donation > 0 && amount < campaign.min_donation && amount < remaining {
            return Err(Error::DonationBelowMinimum);
        }

        let accepted = amount.min(remaining);

        token::Client::new(&env, &campaign.token).transfer(
            &donor,
            env.current_contract_address(),
            &accepted,
        );

        campaign.raised = campaign
            .raised
            .checked_add(accepted)
            .ok_or(Error::InvalidAmount)?;
        storage::save_campaign(&env, &campaign);
        let previous = storage::contribution(&env, campaign_id, &donor);
        storage::set_contribution(&env, campaign_id, &donor, previous + accepted);

        Donated {
            campaign_id,
            donor: donor.clone(),
            amount: accepted,
        }
        .publish(&env);

        Ok(accepted)
    }

    // ─── Sponsor matching ─────────────────────────────────────────────────────

    /// Deposits a sponsor matching pool for `campaign_id`.
    ///
    /// The sponsor pre-funds the pool with `amount` tokens. For each
    /// subsequent call to [`apply_matching`], the contract matches eligible
    /// donations at `ratio_bps` basis points up to `cap`. `ratio_bps` must be
    /// between 1 and 10 000 inclusive. `cap` and `amount` must both be
    /// positive and equal. Only one pool per sponsor per campaign is allowed.
    /// Emits [`SponsorPoolDeposited`].
    ///
    /// # Errors
    /// - [`Error::InvalidMatchingConfig`]: `ratio_bps` is 0 or above 10 000,
    ///   `cap` or `amount` are non-positive, or `amount != cap`.
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::CampaignNotActive`] / [`Error::CampaignExpired`]: campaign
    ///   is not open.
    /// - [`Error::SponsorPoolExists`]: a pool for this sponsor and campaign
    ///   already exists.
    pub fn deposit_sponsor_pool(
        env: Env,
        sponsor: Address,
        campaign_id: u64,
        ratio_bps: u32,
        cap: i128,
        amount: i128,
    ) -> Result<(), Error> {
        sponsor.require_auth();

        if ratio_bps == 0 || ratio_bps > MAX_RATIO_BPS {
            return Err(Error::InvalidMatchingConfig);
        }
        if cap <= 0 || amount <= 0 {
            return Err(Error::InvalidMatchingConfig);
        }
        if amount != cap {
            return Err(Error::InvalidMatchingConfig);
        }

        let campaign = storage::campaign(&env, campaign_id)?;
        Self::ensure_open(&env, &campaign)?;

        if storage::sponsor_pool(&env, campaign_id, &sponsor).is_some() {
            return Err(Error::SponsorPoolExists);
        }

        token::Client::new(&env, &campaign.token).transfer(
            &sponsor,
            env.current_contract_address(),
            &amount,
        );

        let pool = SponsorPool {
            sponsor: sponsor.clone(),
            campaign_id,
            ratio_bps,
            cap,
            deposited: amount,
            remaining: amount,
            matched: 0,
        };
        storage::save_sponsor_pool(&env, &pool);

        SponsorPoolDeposited {
            campaign_id,
            sponsor,
            amount,
            ratio_bps,
            cap,
        }
        .publish(&env);

        Ok(())
    }

    /// Applies sponsor matching for a donation, crediting matched tokens to
    /// the campaign's raised total.
    ///
    /// Any account may call this. The match is computed as
    /// `donation_amount * ratio_bps / 10_000`, clamped to the pool's cap
    /// headroom, remaining balance, and campaign headroom. Returns the actual
    /// matched amount (may be `0` if the pool is exhausted or the donation is
    /// too small). Emits [`MatchingApplied`] when the matched amount is > 0.
    ///
    /// # Errors
    /// - [`Error::InvalidAmount`]: `donation_amount` is zero or negative, or
    ///   the multiplication overflows.
    /// - [`Error::SponsorPoolNotFound`]: no pool exists for this sponsor and
    ///   campaign.
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::CampaignNotActive`] / [`Error::CampaignExpired`]: campaign
    ///   is not open.
    pub fn apply_matching(
        env: Env,
        sponsor: Address,
        campaign_id: u64,
        donor: Address,
        donation_amount: i128,
    ) -> Result<i128, Error> {
        if donation_amount <= 0 {
            return Err(Error::InvalidAmount);
        }

        let mut pool =
            storage::sponsor_pool(&env, campaign_id, &sponsor).ok_or(Error::SponsorPoolNotFound)?;

        let mut campaign = storage::campaign(&env, campaign_id)?;
        Self::ensure_open(&env, &campaign)?;

        let raw_match = donation_amount
            .checked_mul(pool.ratio_bps as i128)
            .ok_or(Error::InvalidAmount)?
            / 10_000_i128;

        if raw_match <= 0 {
            return Ok(0);
        }

        let cap_remaining = pool.cap - pool.matched;
        let pool_limit = pool.remaining;
        let campaign_headroom = campaign.goal - campaign.raised;

        let matched_amount = raw_match
            .min(cap_remaining)
            .min(pool_limit)
            .min(campaign_headroom);

        if matched_amount <= 0 {
            return Ok(0);
        }

        pool.remaining -= matched_amount;
        pool.matched += matched_amount;
        storage::save_sponsor_pool(&env, &pool);

        campaign.raised += matched_amount;
        storage::save_campaign(&env, &campaign);

        let prev = storage::contribution(&env, campaign_id, &sponsor);
        storage::set_contribution(&env, campaign_id, &sponsor, prev + matched_amount);

        MatchingApplied {
            campaign_id,
            sponsor: sponsor.clone(),
            donor,
            donation_amount,
            matched_amount,
        }
        .publish(&env);

        Ok(matched_amount)
    }

    /// Returns the sponsor's unmatched pool balance after the campaign ends.
    ///
    /// Can only be called once the campaign is no longer active (completed,
    /// cancelled, or past its deadline). The remaining pool balance is
    /// transferred back to `sponsor` and the pool record is deleted. Emits
    /// [`SponsorPoolReturned`] and returns the amount returned.
    ///
    /// # Errors
    /// - [`Error::SponsorPoolNotFound`]: no pool exists for this sponsor and
    ///   campaign.
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::PoolNotReturnable`]: campaign is still active and has not
    ///   yet expired.
    pub fn return_sponsor_pool(
        env: Env,
        sponsor: Address,
        campaign_id: u64,
    ) -> Result<i128, Error> {
        sponsor.require_auth();

        let pool =
            storage::sponsor_pool(&env, campaign_id, &sponsor).ok_or(Error::SponsorPoolNotFound)?;

        let campaign = storage::campaign(&env, campaign_id)?;

        let expired = Self::is_expired(&env, &campaign);
        let ended = campaign.status != CampaignStatus::Active || expired;
        if !ended {
            return Err(Error::PoolNotReturnable);
        }

        let remaining = pool.remaining;
        storage::remove_sponsor_pool(&env, campaign_id, &sponsor);

        if remaining > 0 {
            token::Client::new(&env, &campaign.token).transfer(
                &env.current_contract_address(),
                &sponsor,
                &remaining,
            );
        }

        SponsorPoolReturned {
            campaign_id,
            sponsor,
            amount: remaining,
        }
        .publish(&env);

        Ok(remaining)
    }

    // ─── Pledges ──────────────────────────────────────────────────────────────

    /// Records a pledge from `donor` for `campaign_id`.
    ///
    /// A donor creates a pledge for a campaign. The donor must have granted
    /// the Aidline contract a token allowance of at least `pledged_amount`
    /// before calling this. The pledge is recorded persistently and funds are
    /// pulled proportionally when milestones are approved.
    ///
    /// `pledged_amount` must be > 0. The campaign must be active and not
    /// expired. Emits [`PledgeCreated`] and returns the pledge ID.
    ///
    /// # Errors
    /// - [`Error::InvalidPledge`]: `pledged_amount` is zero or negative, or
    ///   the donor's current token allowance is below `pledged_amount`.
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::CampaignNotActive`] / [`Error::CampaignExpired`]: campaign
    ///   is not open.
    pub fn create_pledge(
        env: Env,
        donor: Address,
        campaign_id: u64,
        pledged_amount: i128,
    ) -> Result<u64, Error> {
        donor.require_auth();

        if pledged_amount <= 0 {
            return Err(Error::InvalidPledge);
        }

        let campaign = storage::campaign(&env, campaign_id)?;
        Self::ensure_open(&env, &campaign)?;

        // Verify the donor has granted sufficient allowance.
        // We do not transfer tokens here, they are pulled at milestone approval.
        let tok = token::Client::new(&env, &campaign.token);
        let allowance = tok.allowance(&donor, &env.current_contract_address());
        if allowance < pledged_amount {
            return Err(Error::InvalidPledge);
        }

        let pledge_id = storage::next_pledge_id(&env);
        let pledge = Pledge {
            pledge_id,
            donor: donor.clone(),
            campaign_id,
            pledged_amount,
            pulled_amount: 0,
            active: true,
        };
        storage::save_pledge(&env, &pledge);

        PledgeCreated {
            pledge_id,
            campaign_id,
            donor,
            pledged_amount,
        }
        .publish(&env);

        Ok(pledge_id)
    }

    /// Cancels an active pledge, marking it inactive.
    ///
    /// Only the donor who made the pledge can cancel it. Milestone pulls and
    /// settlements will skip cancelled pledges without error. Emits [`PledgeCancelled`].
    ///
    /// # Errors
    /// - [`Error::InvalidPledge`]: no pledge with `pledge_id` exists.
    /// - [`Error::Unauthorized`]: caller is not the donor of the pledge.
    /// - [`Error::PledgeAlreadyCancelled`]: the pledge has already been cancelled or is inactive.
    pub fn cancel_pledge(env: Env, donor: Address, pledge_id: u64) -> Result<(), Error> {
        donor.require_auth();

        let mut pledge = storage::pledge(&env, pledge_id).ok_or(Error::InvalidPledge)?;
        if pledge.donor != donor {
            return Err(Error::Unauthorized);
        }
        if !pledge.active {
            return Err(Error::PledgeAlreadyCancelled);
        }

        pledge.active = false;
        storage::save_pledge(&env, &pledge);

        PledgeCancelled {
            pledge_id,
            campaign_id: pledge.campaign_id,
            donor,
        }
        .publish(&env);

        Ok(())
    }

    /// Releases an emergency fast-track advance for an `Emergency` campaign.
    ///
    /// Only the campaign's registered verifier may call this. Can only be
    /// used once per campaign and only on `Emergency` campaigns. The advance
    /// is capped at 20% of `campaign.goal` and cannot exceed the currently
    /// available escrow (`raised - released`). Emits
    /// [`EmergencyAdvanceReleased`] and returns the amount transferred.
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::NotEmergencyCampaign`]: campaign `kind` is not `Emergency`.
    /// - [`Error::NotVerifier`]: the campaign's verifier is no longer
    ///   registered.
    /// - [`Error::CampaignNotActive`] / [`Error::CampaignExpired`]: campaign
    ///   is not open.
    /// - [`Error::AdvanceAlreadyTaken`]: the fast-track has already been used
    ///   on this campaign.
    /// - [`Error::AdvanceExceedsEscrow`]: no funds are currently in escrow.
    pub fn emergency_fast_track(env: Env, campaign_id: u64) -> Result<i128, Error> {
        let mut campaign = storage::campaign(&env, campaign_id)?;
        campaign.verifier.require_auth();

        if storage::is_paused(&env) {
            return Err(Error::Paused);
        }

        // Only Emergency campaigns may use the fast track.
        if campaign.kind != CampaignKind::Emergency {
            return Err(Error::NotEmergencyCampaign);
        }
        if !storage::is_verifier(&env, &campaign.verifier) {
            return Err(Error::NotVerifier);
        }
        Self::ensure_open(&env, &campaign)?;

        // Fast track can only be used once.
        if campaign.emergency_advance > 0 {
            return Err(Error::AdvanceAlreadyTaken);
        }

        // Cap: 20% of goal, rounded down (favors the contract, never exceeds).
        let cap = campaign.goal * EMERGENCY_ADVANCE_BPS / BPS_DENOM;

        // Available escrow = raised − already released.
        let available = campaign.raised - campaign.released;
        if available <= 0 {
            return Err(Error::AdvanceExceedsEscrow);
        }

        // Advance is the lesser of the 20% cap and available escrow.
        let advance = if available < cap { available } else { cap };

        token::Client::new(&env, &campaign.token).transfer(
            &env.current_contract_address(),
            &campaign.beneficiary,
            &advance,
        );

        // Record: advance is accounted as both released and emergency_advance.
        campaign.released += advance;
        campaign.emergency_advance = advance;
        storage::save_campaign(&env, &campaign);

        EmergencyAdvanceReleased {
            campaign_id,
            verifier: campaign.verifier.clone(),
            milestone_index: 0,
            amount: advance,
        }
        .publish(&env);

        Ok(advance)
    }

    /// Approves the next milestone for a campaign as `verifier`.
    ///
    /// For single-verifier campaigns, releases the milestone immediately.
    /// For multisig campaigns, records `verifier`'s approval and releases the
    /// milestone once the campaign's `threshold` is met. Returns the scheduled
    /// milestone amount if released, or `0` if more approvals are required.
    /// Emits [`MilestoneApproved`] on each approval, and [`MilestoneReleased`]
    /// when the threshold is reached.
    ///
    /// # Errors
    /// - [`Error::DuplicateApproval`]: `verifier` has already approved this milestone.
    /// - [`Error::NotVerifier`]: `verifier` is not an assigned verifier for this campaign
    ///   or is not currently registered.
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::CampaignNotActive`] / [`Error::CampaignExpired`]: campaign is not open.
    /// - [`Error::NoMilestonesLeft`]: all milestones have already been released.
    /// - [`Error::MilestoneNotFunded`]: raised funds insufficient to cover milestone.
    pub fn approve_milestone_multisig(
        env: Env,
        campaign_id: u64,
        verifier: Address,
        proof_uri: String,
    ) -> Result<i128, Error> {
        Self::internal_approve_milestone(&env, campaign_id, verifier, proof_uri)
    }

    /// Approves the next milestone for `campaign_id` and pays it to the
    /// beneficiary.
    ///
    /// In a single-verifier campaign, authorizes on the campaign's registered
    /// verifier and releases the milestone. For multisig campaigns with
    /// `threshold > 1`, callers should use [`approve_milestone_multisig`] to
    /// identify and authorize which verifier is signing.
    ///
    /// # Errors
    /// - [`Error::UriTooLong`]: `proof_uri` exceeds [`MAX_URI_LENGTH`] bytes.
    /// - [`Error::Unauthorized`]: campaign has multiple verifiers requiring specific authorization.
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::NotVerifier`]: the campaign's verifier is no longer registered.
    /// - [`Error::CampaignNotActive`] / [`Error::CampaignExpired`]: campaign is not open.
    /// - [`Error::NoMilestonesLeft`]: all milestones have already been released.
    /// - [`Error::MilestoneNotFunded`]: raised funds insufficient to cover the next milestone.
    pub fn approve_milestone(env: Env, campaign_id: u64, proof_uri: String) -> Result<i128, Error> {
        let campaign = storage::campaign(&env, campaign_id)?;
        if campaign.verifiers.len() > 1 && campaign.threshold > 1 {
            return Err(Error::Unauthorized);
        }
        Self::internal_approve_milestone(&env, campaign_id, campaign.verifier.clone(), proof_uri)
    }

    /// Records a verifier's rejection of the next pending milestone with an explanatory reason URI.
    ///
    /// Only the campaign's registered verifier may call this. Does not move funds or advance
    /// milestone progress. Emits [`MilestoneRejected`].
    ///
    /// # Errors
    /// - [`Error::UriTooLong`]: `reason_uri` exceeds [`MAX_URI_LENGTH`] bytes.
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::NotVerifier`]: the campaign verifier is no longer registered.
    /// - [`Error::CampaignNotActive`] / [`Error::CampaignExpired`]: campaign is not open.
    /// - [`Error::NoMilestonesLeft`]: all milestones have already been released.
    pub fn reject_milestone(env: Env, campaign_id: u64, reason_uri: String) -> Result<(), Error> {
        if reason_uri.len() > MAX_URI_LENGTH {
            return Err(Error::UriTooLong);
        }

        let campaign = storage::campaign(&env, campaign_id)?;
        campaign.verifier.require_auth();

        if !storage::is_verifier(&env, &campaign.verifier) {
            return Err(Error::NotVerifier);
        }

        Self::ensure_open(&env, &campaign)?;

        let index = campaign.milestones_released;
        if index >= campaign.milestones.len() {
            return Err(Error::NoMilestonesLeft);
        }

        MilestoneRejected {
            campaign_id,
            index,
            reason_uri,
        }
        .publish(&env);

        Ok(())
    }

    fn internal_approve_milestone(
        env: &Env,
        campaign_id: u64,
        verifier: Address,
        proof_uri: String,
    ) -> Result<i128, Error> {
        if proof_uri.len() > MAX_URI_LENGTH {
            return Err(Error::UriTooLong);
        }
        verifier.require_auth();

        if storage::is_paused(env) {
            return Err(Error::Paused);
        }

        let mut campaign = storage::campaign(env, campaign_id)?;
        if !campaign.verifiers.contains(&verifier) {
            return Err(Error::NotVerifier);
        }
        if !storage::is_verifier(env, &verifier) {
            return Err(Error::NotVerifier);
        }
        Self::ensure_open(env, &campaign)?;

        let index = campaign.milestones_released;
        let milestone_amount = campaign
            .milestones
            .get(index)
            .ok_or(Error::NoMilestonesLeft)?;

        let mut approvals = storage::milestone_approvals(env, campaign_id, index);
        if approvals.contains(&verifier) {
            return Err(Error::DuplicateApproval);
        }
        approvals.push_back(verifier.clone());
        storage::save_milestone_approvals(env, campaign_id, index, &approvals);

        MilestoneApproved {
            campaign_id,
            milestone_index: index,
            verifier,
            approvals_count: approvals.len(),
            threshold: campaign.threshold,
        }
        .publish(env);

        if approvals.len() < campaign.threshold {
            return Ok(0);
        }

        // Threshold reached! Release the milestone.
        let pledge_count = storage::next_pledge_id_peek(env);
        let total_pledged_pulled = Self::pull_pledges(
            env,
            campaign_id,
            milestone_amount,
            pledge_count,
            &mut campaign,
        );

        PledgeSettlement {
            campaign_id,
            milestone_index: index,
            total_pledged_pulled,
        }
        .publish(env);

        let already_paid = if index == 0 {
            campaign.emergency_advance
        } else {
            0
        };
        let remaining = milestone_amount - already_paid;

        let available = campaign.raised - campaign.released;
        if available < remaining {
            return Err(Error::MilestoneNotFunded);
        }

        let fee_bps = storage::platform_fee(env);
        let treasury = storage::treasury(env);
        let fee = if fee_bps > 0 && treasury.is_some() {
            let raw_fee = milestone_amount.checked_mul(fee_bps as i128).unwrap_or(0) / BPS_DENOM;
            raw_fee.min(remaining)
        } else {
            0
        };

        let beneficiary_payout = remaining - fee;

        if beneficiary_payout > 0 {
            token::Client::new(env, &campaign.token).transfer(
                &env.current_contract_address(),
                &campaign.beneficiary,
                &beneficiary_payout,
            );
        }

        if fee > 0
            && let Some(ref treasury_addr) = treasury
        {
            token::Client::new(env, &campaign.token).transfer(
                &env.current_contract_address(),
                treasury_addr,
                &fee,
            );
        }

        campaign.released += remaining;
        campaign.milestones_released += 1;
        if campaign.milestones_released == campaign.milestones.len() {
            campaign.status = CampaignStatus::Completed;
        }
        storage::save_campaign(env, &campaign);

        MilestoneReleased {
            campaign_id,
            index,
            amount: milestone_amount,
            fee,
            proof_uri,
        }
        .publish(env);
        Ok(milestone_amount)
    }

    /// Stops a campaign early so donors can reclaim unreleased funds.
    ///
    /// Only the campaign's creator or the admin may call this. The campaign
    /// must currently be `Active`. Emits [`CampaignCancelled`].
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::Unauthorized`]: caller is neither the creator nor the admin.
    /// - [`Error::CampaignNotActive`]: campaign is not in `Active` status.
    pub fn cancel_campaign(env: Env, caller: Address, campaign_id: u64) -> Result<(), Error> {
        caller.require_auth();
        let mut campaign = storage::campaign(&env, campaign_id)?;
        if caller != campaign.creator && caller != storage::admin(&env) {
            return Err(Error::Unauthorized);
        }
        if campaign.status != CampaignStatus::Active {
            return Err(Error::CampaignNotActive);
        }

        campaign.status = CampaignStatus::Cancelled;
        storage::save_campaign(&env, &campaign);

        CampaignCancelled { campaign_id }.publish(&env);
        Ok(())
    }

    /// Returns the donor's pro rata share of unreleased escrow funds.
    ///
    /// A refund is available when the campaign is cancelled, past its
    /// deadline, or a per-milestone due date has been missed. The refund
    /// amount is `contribution * (raised - released) / raised`. After the
    /// transfer the donor's contribution record is zeroed. Emits [`Refunded`]
    /// and returns the amount transferred.
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::RefundNotAvailable`]: campaign is still active, not expired,
    ///   and no milestone is overdue.
    /// - [`Error::NothingToRefund`]: `donor` has no recorded contribution.
    pub fn refund(env: Env, donor: Address, campaign_id: u64) -> Result<i128, Error> {
        donor.require_auth();
        Self::execute_refund(&env, &donor, campaign_id)
    }

    /// Triggers a refund on behalf of `donor` by any account.
    ///
    /// Tokens are always transferred to `donor`, never to the caller.
    /// Requires no authorization from `donor`, enabling relayers, NGOs, or
    /// keepers to push refunds to donors without donor transaction fees or interaction.
    /// Emits [`Refunded`] and returns the amount transferred.
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::RefundNotAvailable`]: campaign is still active, not expired,
    ///   and no milestone is overdue.
    /// - [`Error::NothingToRefund`]: `donor` has no recorded contribution.
    pub fn refund_for(env: Env, donor: Address, campaign_id: u64) -> Result<i128, Error> {
        Self::execute_refund(&env, &donor, campaign_id)
    }

    fn execute_refund(env: &Env, donor: &Address, campaign_id: u64) -> Result<i128, Error> {
        let mut campaign = storage::campaign(env, campaign_id)?;

        let expired = Self::is_expired(env, &campaign);

        let is_overdue = Self::is_overdue(env, &campaign);
        let ended = campaign.status == CampaignStatus::Cancelled || expired;

        if !ended && !is_overdue {
            return Err(Error::RefundNotAvailable);
        }

        let contributed = storage::contribution(env, campaign_id, donor);
        if contributed == 0 {
            return Err(Error::NothingToRefund);
        }

        let unreleased = campaign.raised - campaign.released;
        let amount = contributed * unreleased / campaign.raised;

        storage::set_contribution(env, campaign_id, donor, 0);
        if amount > 0 {
            token::Client::new(env, &campaign.token).transfer(
                &env.current_contract_address(),
                donor,
                &amount,
            );
        }

        if !ended {
            let released_portion = contributed - amount;
            campaign.raised -= contributed;
            campaign.released -= released_portion;
            storage::save_campaign(env, &campaign);
        }

        Refunded {
            campaign_id,
            donor: donor.clone(),
            amount,
        }
        .publish(env);
        Ok(amount)
    }

    // ─── Issue #4: Verifier reassignment ──────────────────────────────────────

    /// Reassigns an active campaign's verifier to `new_verifier`.
    ///
    /// Only the admin may call this. The campaign must be `Active` and not
    /// expired. `new_verifier` must be a currently registered verifier. This
    /// unblocks campaigns whose original verifier was removed. Emits
    /// [`VerifierReassigned`].
    ///
    /// # Errors
    /// - [`Error::Unauthorized`]: caller is not the admin.
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    /// - [`Error::CampaignNotActive`]: campaign is not in `Active` status.
    /// - [`Error::CampaignExpired`]: campaign deadline has passed.
    /// - [`Error::NotVerifier`]: `new_verifier` is not currently registered.
    pub fn reassign_verifier(
        env: Env,
        campaign_id: u64,
        new_verifier: Address,
    ) -> Result<(), Error> {
        storage::admin(&env).require_auth();

        let mut campaign = storage::campaign(&env, campaign_id)?;
        Self::ensure_open(&env, &campaign)?;

        if campaign.verifier_reassignments >= MAX_VERIFIER_REASSIGNMENTS {
            return Err(Error::MaxVerifierReassignmentsExceeded);
        }

        if !storage::is_verifier(&env, &new_verifier) {
            return Err(Error::NotVerifier);
        }

        let old_verifier = campaign.verifier.clone();
        campaign.verifier = new_verifier.clone();
        let mut verifiers = Vec::new(&env);
        verifiers.push_back(new_verifier.clone());
        campaign.verifiers = verifiers;
        campaign.threshold = 1;
        campaign.verifier_reassignments += 1;
        storage::save_campaign(&env, &campaign);

        VerifierReassigned {
            campaign_id,
            old_verifier,
            new_verifier,
        }
        .publish(&env);

        Ok(())
    }

    // ─── Views ────────────────────────────────────────────────────────────────

    /// Returns the [`Campaign`] for `campaign_id`.
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    pub fn get_campaign(env: Env, campaign_id: u64) -> Result<Campaign, Error> {
        storage::campaign(&env, campaign_id)
    }

    /// Returns the remaining amount needed to reach the campaign goal (`goal - raised`).
    ///
    /// Returns `0` if the campaign goal has already been reached or exceeded.
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    pub fn remaining_to_goal(env: Env, campaign_id: u64) -> Result<i128, Error> {
        let campaign = storage::campaign(&env, campaign_id)?;
        let remaining = campaign.goal.saturating_sub(campaign.raised);
        Ok(remaining.max(0))
    }

    /// Returns the next unreleased milestone index and its scheduled amount `(index, amount)`,
    /// or `None` if all milestones have been released.
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    pub fn next_milestone(env: Env, campaign_id: u64) -> Result<Option<(u32, i128)>, Error> {
        let campaign = storage::campaign(&env, campaign_id)?;
        let index = campaign.milestones_released;
        if let Some(amount) = campaign.milestones.get(index) {
            Ok(Some((index, amount)))
        } else {
            Ok(None)
        }
    }

    /// Extends the persistent storage TTL for `campaign_id`.
    ///
    /// Designed for long-running campaigns (e.g. climate projects) that may experience
    /// prolonged quiet periods. Can be called by anyone without authorization, allowing
    /// off-chain keepers or backend services to periodically ensure the campaign entry survives.
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    pub fn extend_campaign_ttl(env: Env, campaign_id: u64) -> Result<(), Error> {
        storage::extend_campaign_ttl(&env, campaign_id)
    }

    /// Returns the total number of campaigns created (also the next campaign ID).
    pub fn campaign_count(env: Env) -> u64 {
        storage::campaign_count(&env)
    }

    /// Returns the effective status of `campaign_id`.
    ///
    /// If the campaign is stored as [`CampaignStatus::Active`] but the ledger timestamp
    /// has passed its deadline, returns [`CampaignStatus::Expired`]. Otherwise returns
    /// the stored status ([`CampaignStatus::Active`], [`CampaignStatus::Completed`], or
    /// [`CampaignStatus::Cancelled`]).
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    pub fn effective_status(env: Env, campaign_id: u64) -> Result<CampaignStatus, Error> {
        let campaign = storage::campaign(&env, campaign_id)?;
        if Self::is_expired(&env, &campaign) {
            Ok(CampaignStatus::Expired)
        } else {
            Ok(campaign.status)
        }
    }

    /// Returns the number of times `campaign_id`'s verifier has been reassigned.
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    pub fn verifier_reassignments(env: Env, campaign_id: u64) -> Result<u32, Error> {
        let campaign = storage::campaign(&env, campaign_id)?;
        Ok(campaign.verifier_reassignments)
    }

    /// Returns the milestone due dates for `campaign_id`.
    ///
    /// Returns an empty vector for campaigns created without per-milestone due dates.
    ///
    /// # Errors
    /// - [`Error::CampaignNotFound`]: no campaign with `campaign_id` exists.
    pub fn milestone_due_dates(env: Env, campaign_id: u64) -> Result<Vec<u64>, Error> {
        storage::campaign(&env, campaign_id)?;
        Ok(storage::milestone_due_dates(&env, campaign_id).unwrap_or_else(|| Vec::new(&env)))
    }

    /// Returns the total amount `donor` has contributed to `campaign_id`.
    pub fn contribution_of(env: Env, campaign_id: u64, donor: Address) -> i128 {
        storage::contribution(&env, campaign_id, &donor)
    }

    /// Returns `true` if donors can claim refunds for `campaign_id`.
    ///
    /// Mirrors the availability checks in [`refund`]: a campaign is refundable
    /// if it has been cancelled, if it is active and past its deadline, or if
    /// a milestone is overdue. Returns `false` if the campaign is active and on
    /// schedule, completed, or does not exist.
    pub fn is_refundable(env: Env, campaign_id: u64) -> bool {
        let Ok(campaign) = storage::campaign(&env, campaign_id) else {
            return false;
        };
        Self::is_campaign_refundable(&env, &campaign)
    }

    /// Returns the amount `donor` would receive if they claimed a refund right now.
    ///
    /// Uses the same rounding rules as [`refund`] (rounds down in favor of the contract).
    /// Returns 0 if a refund is not available, if the campaign does not exist, or if
    /// `donor` has no contribution or no unreleased balance remains.
    pub fn refundable_amount(env: Env, campaign_id: u64, donor: Address) -> i128 {
        let Ok(campaign) = storage::campaign(&env, campaign_id) else {
            return 0;
        };
        if !Self::is_campaign_refundable(&env, &campaign) {
            return 0;
        }
        let contributed = storage::contribution(&env, campaign_id, &donor);
        if contributed == 0 || campaign.raised == 0 {
            return 0;
        }
        let unreleased = campaign.raised - campaign.released;
        if unreleased <= 0 {
            return 0;
        }
        contributed * unreleased / campaign.raised
    }

    /// Returns `true` if `who` is currently a registered verifier.
    pub fn is_verifier(env: Env, who: Address) -> bool {
        storage::is_verifier(&env, &who)
    }

    /// Returns the current admin address.
    pub fn admin(env: Env) -> Address {
        storage::admin(&env)
    }

    /// Returns the pending admin address nominated via [`propose_admin`], or `None`.
    pub fn pending_admin(env: Env) -> Option<Address> {
        storage::pending_admin(&env)
    }

    /// Returns the token contract address used by all campaigns.
    pub fn token(env: Env) -> Address {
        storage::token(&env)
    }

    /// Returns the crate version of the deployed contract.
    pub fn version(env: Env) -> String {
        String::from_str(&env, env!("CARGO_PKG_VERSION"))
    }

    /// Returns the [`SponsorPool`] for `sponsor` on `campaign_id`, or `None`.
    pub fn get_sponsor_pool(env: Env, campaign_id: u64, sponsor: Address) -> Option<SponsorPool> {
        storage::sponsor_pool(&env, campaign_id, &sponsor)
    }

    /// Returns the [`Pledge`] with the given `pledge_id`, or `None`.
    pub fn get_pledge(env: Env, pledge_id: u64) -> Option<Pledge> {
        storage::pledge(&env, pledge_id)
    }

    /// Returns the list of verifiers who have approved milestone `milestone_index`.
    pub fn get_milestone_approvals(
        env: Env,
        campaign_id: u64,
        milestone_index: u32,
    ) -> Vec<Address> {
        storage::milestone_approvals(&env, campaign_id, milestone_index)
    }

    /// Returns the current platform fee in basis points (default: 0).
    pub fn platform_fee(env: Env) -> u32 {
        storage::platform_fee(&env)
    }

    /// Returns the current platform treasury address, or `None` if not configured.
    pub fn treasury(env: Env) -> Option<Address> {
        storage::treasury(&env)
    }

    /// Returns `true` if the contract is currently paused.
    pub fn is_paused(env: Env) -> bool {
        storage::is_paused(&env)
    }

    // ─── Internal ─────────────────────────────────────────────────────────────

    fn ensure_open(env: &Env, campaign: &Campaign) -> Result<(), Error> {
        if campaign.status != CampaignStatus::Active {
            return Err(Error::CampaignNotActive);
        }
        if Self::is_expired(env, campaign) {
            return Err(Error::CampaignExpired);
        }
        Ok(())
    }

    /// Pull pledge funds proportionally toward `milestone_amount`.
    ///
    /// Returns the total amount actually pulled from pledges.
    ///
    /// Algorithm:
    /// 1. Collect all active pledges for the campaign.
    /// 2. Compute total remaining pledge capacity.
    /// 3. For each pledge compute its proportional share of `milestone_amount`.
    /// 4. Clamp to: min(share, pledge.remaining, allowance).
    /// 5. If pull > 0, transfer and record contribution.
    /// 6. If allowance == 0 or pull == 0, emit PledgeSkipped.
    ///
    /// Rounding: each share is `milestone_amount * pledge.remaining / total_remaining`,
    /// using integer division truncated toward zero. Any unallocated remainder
    /// stays in the milestone's direct-donation funding.
    fn pull_pledges(
        env: &Env,
        campaign_id: u64,
        milestone_amount: i128,
        pledge_count: u64,
        campaign: &mut Campaign,
    ) -> i128 {
        let tok = token::Client::new(env, &campaign.token);
        let contract_addr = env.current_contract_address();

        // Phase 1: gather active pledges for this campaign.
        let mut active_pledges: Vec<Pledge> = Vec::new(env);
        let mut total_remaining: i128 = 0;
        let mut i: u64 = 0;
        while i < pledge_count {
            if let Some(p) = storage::pledge(env, i)
                && p.campaign_id == campaign_id
                && p.active
                && p.pulled_amount < p.pledged_amount
            {
                total_remaining += p.pledged_amount - p.pulled_amount;
                active_pledges.push_back(p);
            }
            i += 1;
        }
        if total_remaining == 0 || active_pledges.is_empty() {
            return 0;
        }

        // Phase 2: pull proportionally.
        let mut total_pulled: i128 = 0;

        for mut pledge in active_pledges.iter() {
            let pledge_remaining = pledge.pledged_amount - pledge.pulled_amount;

            // Proportional share: milestone_amount * pledge_remaining / total_remaining.
            let share = milestone_amount
                .checked_mul(pledge_remaining)
                .unwrap_or(i128::MAX)
                / total_remaining;

            if share <= 0 {
                PledgeSkipped {
                    pledge_id: pledge.pledge_id,
                    campaign_id,
                    donor: pledge.donor.clone(),
                    reason: SKIP_REASON_EXHAUSTED,
                }
                .publish(env);
                continue;
            }

            // Check allowance.
            let allowance = tok.allowance(&pledge.donor, &contract_addr);
            if allowance <= 0 {
                PledgeSkipped {
                    pledge_id: pledge.pledge_id,
                    campaign_id,
                    donor: pledge.donor.clone(),
                    reason: SKIP_REASON_NO_ALLOWANCE,
                }
                .publish(env);
                continue;
            }

            // Clamp to what is actually available.
            let pull = share.min(pledge_remaining).min(allowance);
            if pull <= 0 {
                PledgeSkipped {
                    pledge_id: pledge.pledge_id,
                    campaign_id,
                    donor: pledge.donor.clone(),
                    reason: SKIP_REASON_NO_ALLOWANCE,
                }
                .publish(env);
                continue;
            }

            // Transfer tokens from donor to contract.
            tok.transfer_from(&contract_addr, &pledge.donor, &contract_addr, &pull);

            // Update pledge record.
            pledge.pulled_amount += pull;
            if pledge.pulled_amount >= pledge.pledged_amount {
                pledge.active = false;
            }
            storage::save_pledge(env, &pledge);

            // Record as contribution so donor shares in refunds.
            let prev = storage::contribution(env, campaign_id, &pledge.donor);
            storage::set_contribution(env, campaign_id, &pledge.donor, prev + pull);

            // Increase campaign.raised.
            campaign.raised = campaign.raised.checked_add(pull).unwrap_or(campaign.raised);
            total_pulled += pull;

            PledgePulled {
                pledge_id: pledge.pledge_id,
                campaign_id,
                donor: pledge.donor.clone(),
                pulled_amount: pull,
            }
            .publish(env);
        }

        total_pulled
    }

    fn is_overdue(env: &Env, campaign: &Campaign) -> bool {
        if campaign.status != CampaignStatus::Active {
            return false;
        }
        if let Some(due_dates) = storage::milestone_due_dates(env, campaign.id)
            && let Some(due_date) = due_dates.get(campaign.milestones_released)
            && env.ledger().timestamp() > due_date
        {
            return true;
        }
        false
    }

    fn is_expired(env: &Env, campaign: &Campaign) -> bool {
        campaign.status == CampaignStatus::Active && env.ledger().timestamp() > campaign.deadline
    }

    fn is_campaign_refundable(env: &Env, campaign: &Campaign) -> bool {
        let expired = Self::is_expired(env, campaign);
        let is_overdue = Self::is_overdue(env, campaign);
        let ended = campaign.status == CampaignStatus::Cancelled || expired;

        ended || is_overdue
    }
}
