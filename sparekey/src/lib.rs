#![no_std]
//! email recovery for a normal stellar account.
//!
//! register while you still have your key: store a commitment to your email + an
//! allowance. nothing locked.
//! recover after you lose the device: email the relayer with your new address in
//! the subject. a zk proof shows a mail provider signed it and the sender matches
//! the commitment. destination comes from the signed subject so the relayer can't
//! redirect it. short cancel window.
//!
//! funds only ever go to the signed address or stay put. one email = one recovery
//! (nullifier is global). admin tweaks params, never touches funds.

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

// cap on the delay so admin can't freeze funds by setting it huge
const MAX_DELAY: u64 = 30 * 86_400;
const MAX_ASSETS: u32 = 8;
// stellar address = 56 base32 chars
const ADDRESS_LEN: u32 = 56;

// the groth16 verifier contract
#[contractclient(name = "VerifierClient")]
pub trait Verifier {
    fn verify_proof(env: Env, proof: Proof, public_inputs: Vec<BytesN<32>>) -> bool;
}

#[contract]
pub struct SpareKey;

#[contractimpl]
impl SpareKey {
    // min_delay in seconds. 5 is fine for a demo, prod wants days
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

    // store the email commitment. you also need to approve an allowance on each
    // asset or recovery can't move anything. register_and_approve does both at once.
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

    // register + approve in one call so it's a single signature and can't end up
    // half done
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

    // change the email. blocked if a recovery is already running
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

    // opt out. revoke the allowance yourself by approving zero, we can't do it for you
    pub fn unregister(env: Env, owner: Address) {
        owner.require_auth();
        let _ = get_reg(&env, &owner);
        env.storage().persistent().remove(&DataKey::Reg(owner.clone()));
        env.storage().persistent().remove(&DataKey::Pending(owner.clone()));
        events::Unregistered { owner }.publish(&env);
    }

    // ────────────────────────────────── phase 2: recovery ──────────────────

    // anyone can call this - the person recovering has no key to sign with, so
    // safety is in the proof not the caller. destination comes from the signed
    // subject so whoever submits it can't point it somewhere else.
    pub fn start_recovery(env: Env, owner: Address, proof: Proof, public_inputs: Vec<BytesN<32>>) {
        let reg = get_reg(&env, &owner);
        if env.storage().persistent().has(&DataKey::Pending(owner.clone())) {
            panic_with_error!(&env, Error::RecoveryInProgress);
        }
        if public_inputs.len() != PI_COUNT {
            panic_with_error!(&env, Error::BadPublicInputs);
        }

        // which dkim key signed it. without this check anyone could sign their own
        let pubkey_hash = public_inputs.get_unchecked(PI_PUBKEY_HASH);
        if !env.storage().persistent().has(&DataKey::DkimKey(pubkey_hash.clone())) {
            panic_with_error!(&env, Error::UnknownDkimKey);
        }
        if public_inputs.get_unchecked(PI_COMMITMENT) != reg.commitment {
            panic_with_error!(&env, Error::WrongCommitment);
        }
        // salt is public so it has to match the registered one, else someone could
        // pick a salt that makes their address hash to this commitment
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

        // burn the email first
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

    // owner showed up, cancel it (needs their key, which they clearly have if they
    // can call this). the nullifier stays burned so you can't just resubmit.
    pub fn cancel_recovery(env: Env, owner: Address) {
        owner.require_auth();
        let pending = get_pending(&env, &owner);
        env.storage().persistent().remove(&DataKey::Pending(owner.clone()));
        events::RecoveryCancelled { owner, destination: pending.destination }.publish(&env);
    }

    // anyone can call this once the delay's up, so recovery doesn't depend on us
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
            // take whatever's smaller instead of reverting - owner might be gone, so
            // failing the whole thing could strand everything
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
    // params only. can't move funds, redirect a recovery, or touch a registration.

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

    // add a dkim key hash (the one the circuit outputs)
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

    // providers rotate keys, and a bad key needs removing. pending recoveries unaffected.
    pub fn remove_dkim_key(env: Env, pubkey_hash: BytesN<32>) {
        require_admin(&env);
        env.storage().persistent().remove(&DataKey::DkimKey(pubkey_hash));
        touch(&env);
    }

    // swap the verifier - lets us upgrade to a real ceremony or a new proof system
    // without touching funds. also the scariest admin power (a bad verifier accepts
    // forged proofs) so put it behind a multisig + timelock.
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
    // so a wallet can show where a proof would pay out before submitting
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

// rebuild the destination from the subject the circuit exposed.
// circuit packs it 31 bytes per field element, little-endian, across the payout
// signals. signals come in big-endian so reverse each, take the low 31 bytes, drop
// the padding. has to be exactly a 56-char address, nothing else, no ambiguity.
fn destination_from_subject(env: &Env, public_inputs: &Vec<BytesN<32>>) -> Address {
    let mut raw = Bytes::new(env);
    for i in 0..PI_PAYOUT_CHUNKS {
        let be = public_inputs.get_unchecked(PI_PAYOUT_0 + i).to_array();
        // big-endian, so be[31] is the low byte. top byte must be unused.
        if be[0] != 0 {
            panic_with_error!(env, Error::BadDestination);
        }
        for j in 0..31u32 {
            raw.push_back(be[(31 - j) as usize]);
        }
    }

    // drop the padding
    let mut len = raw.len();
    while len > 0 && raw.get_unchecked(len - 1) == 0 {
        len -= 1;
    }
    if len != ADDRESS_LEN {
        panic_with_error!(env, Error::BadDestination);
    }
    let trimmed = raw.slice(0..len);

    // would get rejected later anyway, but fail early for a clean error
    for i in 0..trimmed.len() {
        let c = trimmed.get_unchecked(i);
        let ok = (c >= b'A' && c <= b'Z') || (c >= b'2' && c <= b'7');
        if !ok {
            panic_with_error!(env, Error::BadDestination);
        }
    }
    Address::from_string_bytes(&trimmed)
}
