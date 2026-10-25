#![no_std]
//! SpareKey — email recovery for ordinary Stellar accounts.
//!
//! Phase 1, registration: while the owner still holds their key, they record a
//! commitment to their email address and grant this contract a standing
//! allowance. Nothing moves and nothing is locked.
//!
//! Phase 2, recovery: the owner emails the relayer with their NEW address as
//! the subject. A zero-knowledge proof shows that a real mail provider signed
//! that email, that the sender matches the stored commitment, and what the
//! subject said. The destination comes out of the signed subject, never from
//! the caller, so whoever submits the proof cannot redirect the funds. A delay
//! then runs, during which the owner can cancel.
//!
//! Three properties this contract must not lose:
//!
//! 1. Funds can only ever reach the address named in a signed email, or stay
//!    where they are. The admin cannot move them, and neither can we.
//! 2. One email authorises one recovery, forever (the nullifier is global).
//! 3. Every admin power is a parameter, never authority over funds.

mod events;
mod types;
pub use types::*;

#[cfg(test)]
mod test;

use soroban_sdk::{
    contract, contractclient, contractimpl, panic_with_error, token, Address, Bytes, BytesN, Env,
    Symbol, Vec,
};

const DAY_LEDGERS: u32 = 17_280;
const TTL_THRESHOLD: u32 = 30 * DAY_LEDGERS;
const TTL_EXTEND: u32 = 120 * DAY_LEDGERS;

/// Upper bound on the admin-set delay. The admin can tune the wait, but cannot
/// set it so long that funds are effectively frozen.
const MAX_DELAY: u64 = 30 * 86_400;
const MAX_ASSETS: u32 = 8;
/// A Stellar public address is 56 characters of base32.
const ADDRESS_LEN: u32 = 56;

/// The generated Groth16 verifier for the claim circuit.
#[contractclient(name = "VerifierClient")]
pub trait Verifier {
    fn verify_proof(env: Env, proof: Proof, public_inputs: Vec<BytesN<32>>) -> bool;
}

#[contract]
pub struct SpareKey;

#[contractimpl]
impl SpareKey {
    /// `min_delay` is in seconds and starts at whatever is passed here (5 for
    /// demos). Production wants days, not seconds.
    pub fn __constructor(env: Env, admin: Address, verifier: Address, min_delay: u64) {
        let s = env.storage().instance();
        if s.has(&DataKey::Admin) {
            panic_with_error!(&env, Error::AlreadyInitialized);
        }
        if min_delay > MAX_DELAY {
            panic_with_error!(&env, Error::InvalidParams);
        }
        s.set(&DataKey::Admin, &admin);
        s.set(&DataKey::Verifier, &verifier);
        s.set(&DataKey::MinDelay, &min_delay);
        s.extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
    }

    // ────────────────────────────────── phase 1: registration ──────────────

    /// Record the email commitment. The caller must also grant this contract an
    /// allowance on every asset listed, which is what lets a later recovery
    /// move anything. `register_and_approve` does both in one transaction.
    pub fn register(
        env: Env,
        owner: Address,
        commitment: BytesN<32>,
        salt: BytesN<32>,
        assets: Vec<AssetSpec>,
    ) {
        owner.require_auth();
        if env.storage().persistent().has(&DataKey::Reg(owner.clone())) {
            panic_with_error!(&env, Error::AlreadyRegistered);
        }
        check_assets(&env, &assets);

        let reg = Registration {
            owner: owner.clone(),
            commitment: commitment.clone(),
            salt: salt.clone(),
            assets,
            registered_at: env.ledger().timestamp(),
        };
        put_reg(&env, &owner, &reg);
        events::Registered { owner, commitment, salt }.publish(&env);
    }

    /// One-transaction setup: register, then grant the allowance on each asset
    /// from inside the same call, so the wallet asks for a single signature and
    /// the two can never end up half-applied.
    pub fn register_and_approve(
        env: Env,
        owner: Address,
        commitment: BytesN<32>,
        salt: BytesN<32>,
        assets: Vec<AssetSpec>,
        amount: i128,
        expiration_ledger: u32,
    ) {
        Self::register(env.clone(), owner.clone(), commitment, salt, assets.clone());
        let me = env.current_contract_address();
        for a in assets.iter() {
            token::TokenClient::new(&env, &a.token)
                .approve(&owner, &me, &amount, &expiration_ledger);
        }
    }

    /// Point the registration at a different email. Refused while a recovery is
    /// in flight, so an attacker who somehow started one cannot also move the
    /// goalposts.
    pub fn update_email(env: Env, owner: Address, commitment: BytesN<32>, salt: BytesN<32>) {
        owner.require_auth();
        let mut reg = get_reg(&env, &owner);
        if env.storage().persistent().has(&DataKey::Pending(owner.clone())) {
            panic_with_error!(&env, Error::RecoveryInProgress);
        }
        reg.commitment = commitment.clone();
        reg.salt = salt;
        put_reg(&env, &owner, &reg);
        events::EmailChanged { owner, commitment }.publish(&env);
    }

    /// Withdraw from the scheme entirely. The allowance should be revoked
    /// separately by approving zero; this contract cannot do that for you.
    pub fn unregister(env: Env, owner: Address) {
        owner.require_auth();
        let _ = get_reg(&env, &owner);
        env.storage().persistent().remove(&DataKey::Reg(owner.clone()));
        env.storage().persistent().remove(&DataKey::Pending(owner.clone()));
        events::Unregistered { owner }.publish(&env);
    }

    // ────────────────────────────────── phase 2: recovery ──────────────────

    /// Permissionless: anyone may submit, because the person recovering has no
    /// key to authorise with. Safety comes from the proof, not the caller.
    ///
    /// The destination is read out of the signed Subject. A relayer holding the
    /// proof therefore cannot point it anywhere else, which is the difference
    /// between this and trusting the relayer.
    pub fn start_recovery(env: Env, owner: Address, proof: Proof, public_inputs: Vec<BytesN<32>>) {
        let reg = get_reg(&env, &owner);
        if env.storage().persistent().has(&DataKey::Pending(owner.clone())) {
            panic_with_error!(&env, Error::RecoveryInProgress);
        }
        if public_inputs.len() != PI_COUNT {
            panic_with_error!(&env, Error::BadPublicInputs);
        }

        // Which mail provider signed it. Without this check the proof only says
        // "signed by some key", and anyone could generate their own.
        let pubkey_hash = public_inputs.get_unchecked(PI_PUBKEY_HASH);
        if !env.storage().persistent().has(&DataKey::DkimKey(pubkey_hash.clone())) {
            panic_with_error!(&env, Error::UnknownDkimKey);
        }
        if public_inputs.get_unchecked(PI_COMMITMENT) != reg.commitment {
            panic_with_error!(&env, Error::WrongCommitment);
        }
        // The salt is a public input, so it must be the one registered: a
        // different salt would let an attacker's address hash to this
        // commitment.
        if public_inputs.get_unchecked(PI_SALT) != reg.salt {
            panic_with_error!(&env, Error::WrongSalt);
        }

        let nullifier = public_inputs.get_unchecked(PI_NULLIFIER);
        if env.storage().persistent().has(&DataKey::Nullifier(nullifier.clone())) {
            panic_with_error!(&env, Error::NullifierUsed);
        }

        let verifier: Address = get(&env, &DataKey::Verifier);
        if !VerifierClient::new(&env, &verifier).verify_proof(&proof, &public_inputs) {
            panic_with_error!(&env, Error::BadProof);
        }

        let destination = destination_from_subject(&env, &public_inputs);

        // Spend the email before anything else can happen with it.
        env.storage().persistent().set(&DataKey::Nullifier(nullifier.clone()), &true);
        env.storage().persistent().extend_ttl(
            &DataKey::Nullifier(nullifier.clone()),
            TTL_THRESHOLD,
            TTL_EXTEND,
        );

        let min_delay: u64 = get(&env, &DataKey::MinDelay);
        let unlock_at = env.ledger().timestamp() + min_delay;
        let pending = Pending {
            destination: destination.clone(),
            unlock_at,
            nullifier,
            started_at: env.ledger().timestamp(),
        };
        env.storage().persistent().set(&DataKey::Pending(owner.clone()), &pending);
        env.storage().persistent().extend_ttl(
            &DataKey::Pending(owner.clone()),
            TTL_THRESHOLD,
            TTL_EXTEND,
        );

        events::RecoveryStarted { owner, destination, unlock_at }.publish(&env);
    }

    /// The owner is still here after all. Cancelling costs them their key, which
    /// they have by definition if they can call this.
    ///
    /// Note the spent nullifier is NOT released: that email stays burned, so a
    /// cancelled attempt cannot simply be resubmitted.
    pub fn cancel_recovery(env: Env, owner: Address) {
        owner.require_auth();
        let pending = get_pending(&env, &owner);
        env.storage().persistent().remove(&DataKey::Pending(owner.clone()));
        events::RecoveryCancelled { owner, destination: pending.destination }.publish(&env);
    }

    /// Permissionless once the delay has passed, so the person recovering is
    /// never blocked on us submitting for them.
    pub fn execute_recovery(env: Env, owner: Address) -> Vec<AssetSpec> {
        let reg = get_reg(&env, &owner);
        let pending = get_pending(&env, &owner);
        if env.ledger().timestamp() < pending.unlock_at {
            panic_with_error!(&env, Error::StillLocked);
        }

        let me = env.current_contract_address();
        let mut moved = Vec::new(&env);
        for a in reg.assets.iter() {
            let client = token::TokenClient::new(&env, &a.token);
            let spendable = client.balance(&owner) - a.floor;
            let allowance = client.allowance(&owner, &me);
            // Take the lesser rather than reverting when one is short: the
            // owner may be unreachable, so a wholesale failure here could be
            // permanent.
            let amount = if spendable < allowance { spendable } else { allowance };
            if amount <= 0 {
                continue;
            }
            client.transfer_from(&me, &owner, &pending.destination, &amount);
            moved.push_back(AssetSpec { token: a.token.clone(), floor: amount });
        }
        if moved.is_empty() {
            panic_with_error!(&env, Error::NothingToRecover);
        }

        env.storage().persistent().remove(&DataKey::Pending(owner.clone()));
        events::Recovered { owner, destination: pending.destination, moved: moved.clone() }
            .publish(&env);
        moved
    }

    // ────────────────────────────────── admin ──────────────────────────────
    // Parameters only. None of these can move funds, redirect a recovery, or
    // alter anyone's registration.

    pub fn set_min_delay(env: Env, seconds: u64) {
        require_admin(&env);
        if seconds > MAX_DELAY {
            panic_with_error!(&env, Error::InvalidParams);
        }
        env.storage().instance().set(&DataKey::MinDelay, &seconds);
        touch(&env);
        events::AdminChange { what: Symbol::new(&env, "min_delay"), value: seconds as i128 }
            .publish(&env);
    }

    /// Register a mail provider's DKIM key hash, as the circuit computes it.
    pub fn add_dkim_key(env: Env, pubkey_hash: BytesN<32>) {
        require_admin(&env);
        env.storage().persistent().set(&DataKey::DkimKey(pubkey_hash.clone()), &true);
        env.storage().persistent().extend_ttl(
            &DataKey::DkimKey(pubkey_hash),
            TTL_THRESHOLD,
            TTL_EXTEND,
        );
        touch(&env);
    }

    /// Providers rotate keys, and a compromised key must be removable.
    /// Recoveries already pending are unaffected.
    pub fn remove_dkim_key(env: Env, pubkey_hash: BytesN<32>) {
        require_admin(&env);
        env.storage().persistent().remove(&DataKey::DkimKey(pubkey_hash));
        touch(&env);
    }

    /// Point at a new verifier. This exists so a proper multi-party ceremony,
    /// or a post-quantum proof system, can replace today's development setup
    /// without moving anyone's funds. It is also the most dangerous admin
    /// power here, since a malicious verifier would accept forged proofs: it
    /// belongs behind a multisig with a public timelock.
    pub fn set_verifier(env: Env, verifier: Address) {
        require_admin(&env);
        env.storage().instance().set(&DataKey::Verifier, &verifier);
        touch(&env);
    }

    pub fn set_admin(env: Env, new_admin: Address) {
        require_admin(&env);
        env.storage().instance().set(&DataKey::Admin, &new_admin);
        touch(&env);
    }

    // ────────────────────────────────── views ──────────────────────────────

    pub fn registration(env: Env, owner: Address) -> Option<Registration> {
        env.storage().persistent().get(&DataKey::Reg(owner))
    }
    pub fn pending(env: Env, owner: Address) -> Option<Pending> {
        env.storage().persistent().get(&DataKey::Pending(owner))
    }
    pub fn is_spent(env: Env, nullifier: BytesN<32>) -> bool {
        env.storage().persistent().has(&DataKey::Nullifier(nullifier))
    }
    pub fn dkim_key_allowed(env: Env, pubkey_hash: BytesN<32>) -> bool {
        env.storage().persistent().has(&DataKey::DkimKey(pubkey_hash))
    }
    pub fn min_delay(env: Env) -> u64 {
        get(&env, &DataKey::MinDelay)
    }
    pub fn verifier(env: Env) -> Address {
        get(&env, &DataKey::Verifier)
    }
    pub fn admin(env: Env) -> Address {
        get(&env, &DataKey::Admin)
    }
    /// Exposed so a wallet can show the user what a proof would pay out to
    /// before anything is submitted.
    pub fn preview_destination(env: Env, public_inputs: Vec<BytesN<32>>) -> Address {
        if public_inputs.len() != PI_COUNT {
            panic_with_error!(&env, Error::BadPublicInputs);
        }
        destination_from_subject(&env, &public_inputs)
    }
}

// ────────────────────────────────── internals ──────────────────────────────

fn get<T: soroban_sdk::TryFromVal<Env, soroban_sdk::Val>>(env: &Env, key: &DataKey) -> T {
    env.storage().instance().get(key).unwrap()
}

fn touch(env: &Env) {
    env.storage().instance().extend_ttl(TTL_THRESHOLD, TTL_EXTEND);
}

fn require_admin(env: &Env) -> Address {
    let admin: Address = get(env, &DataKey::Admin);
    admin.require_auth();
    admin
}

fn check_assets(env: &Env, assets: &Vec<AssetSpec>) {
    if assets.is_empty() || assets.len() > MAX_ASSETS {
        panic_with_error!(env, Error::TooManyAssets);
    }
    for a in assets.iter() {
        if a.floor < 0 {
            panic_with_error!(env, Error::InvalidParams);
        }
    }
}

fn put_reg(env: &Env, owner: &Address, reg: &Registration) {
    env.storage().persistent().set(&DataKey::Reg(owner.clone()), reg);
    env.storage().persistent().extend_ttl(
        &DataKey::Reg(owner.clone()),
        TTL_THRESHOLD,
        TTL_EXTEND,
    );
}

fn get_reg(env: &Env, owner: &Address) -> Registration {
    match env.storage().persistent().get(&DataKey::Reg(owner.clone())) {
        Some(r) => r,
        None => panic_with_error!(env, Error::NotRegistered),
    }
}

fn get_pending(env: &Env, owner: &Address) -> Pending {
    match env.storage().persistent().get(&DataKey::Pending(owner.clone())) {
        Some(p) => p,
        None => panic_with_error!(env, Error::NoRecoveryPending),
    }
}

/// Rebuild the destination address from the subject the circuit revealed.
///
/// The circuit packs the subject 31 bytes per field element, little-endian,
/// across `PI_PAYOUT_CHUNKS` signals. A public signal arrives big-endian, so
/// each is reversed and its low 31 bytes taken, then trailing padding dropped.
/// The result must be exactly a 56-character Stellar address and nothing else,
/// so there is never any parsing ambiguity about what was authorised.
fn destination_from_subject(env: &Env, public_inputs: &Vec<BytesN<32>>) -> Address {
    let mut raw = Bytes::new(env);
    for i in 0..PI_PAYOUT_CHUNKS {
        let be = public_inputs.get_unchecked(PI_PAYOUT_0 + i).to_array();
        // big-endian: be[31] is the least significant byte, so little-endian
        // order is be[31], be[30], ... and the top byte must be unused.
        if be[0] != 0 {
            panic_with_error!(env, Error::BadDestination);
        }
        for j in 0..31u32 {
            raw.push_back(be[(31 - j) as usize]);
        }
    }

    // Drop the zero padding the packing added.
    let mut len = raw.len();
    while len > 0 && raw.get_unchecked(len - 1) == 0 {
        len -= 1;
    }
    if len != ADDRESS_LEN {
        panic_with_error!(env, Error::BadDestination);
    }
    let trimmed = raw.slice(0..len);

    // Any byte that is not base32 would be rejected here anyway, but failing
    // early keeps the error honest.
    for i in 0..trimmed.len() {
        let c = trimmed.get_unchecked(i);
        let ok = (c >= b'A' && c <= b'Z') || (c >= b'2' && c <= b'7');
        if !ok {
            panic_with_error!(env, Error::BadDestination);
        }
    }
    Address::from_string_bytes(&trimmed)
}
