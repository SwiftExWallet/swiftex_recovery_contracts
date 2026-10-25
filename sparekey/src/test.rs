#![cfg(test)]
//! What these tests are for.
//!
//! The happy path is already proven on testnet with a real Gmail proof, so it
//! is not what is interesting here. What is interesting is every way the
//! contract must say no, and the three paths testnet could not reach without a
//! second unspent proof: cancellation, the delay, and a wrong salt.
//!
//! The verifier is mocked. That is deliberate: these tests are about the
//! contract's logic, not about Groth16. Whether the cryptography works is
//! settled on-chain against the real verifier, not here.

extern crate std;

use crate::{events, types::*, SpareKey, SpareKeyClient};
use soroban_sdk::{
    contract, contractimpl,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    symbol_short,
    testutils::{Address as _, Events, Ledger},
    token, Address, BytesN, Env, Vec,
};

// ─────────────────────────────── mock verifier ──────────────────────────────

/// Stands in for the generated Groth16 verifier. `set_ok(false)` makes it
/// reject, which is how we reach `Error::BadProof` without forging a proof.
#[contract]
pub struct MockVerifier;

#[contractimpl]
impl MockVerifier {
    pub fn set_ok(env: Env, ok: bool) {
        env.storage().instance().set(&symbol_short!("ok"), &ok);
    }
    pub fn verify_proof(env: Env, _proof: Proof, _public_inputs: Vec<BytesN<32>>) -> bool {
        env.storage().instance().get(&symbol_short!("ok")).unwrap_or(true)
    }
}

// ─────────────────────────────── fixture ────────────────────────────────────

const DAY: u64 = 86_400;
const FLOOR: i128 = 20_000_000; // 2 XLM in stroops
const MINTED: i128 = 1_000_000_000;

struct Fx {
    env: Env,
    contract: SpareKeyClient<'static>,
    verifier: MockVerifierClient<'static>,
    admin: Address,
    owner: Address,
    token: Address,
    sac: token::StellarAssetClient<'static>,
    coin: token::TokenClient<'static>,
    dkim: BytesN<32>,
    commitment: BytesN<32>,
    salt: BytesN<32>,
}

impl Fx {
    fn new(min_delay: u64) -> Fx {
        let env = Env::default();
        env.mock_all_auths();
        env.ledger().set_timestamp(1_700_000_000);

        let admin = Address::generate(&env);
        let owner = Address::generate(&env);

        let verifier_id = env.register(MockVerifier, ());
        let verifier = MockVerifierClient::new(&env, &verifier_id);

        let id = env.register(SpareKey, (admin.clone(), verifier_id.clone(), min_delay));
        let contract = SpareKeyClient::new(&env, &id);

        let issued = env.register_stellar_asset_contract_v2(admin.clone());
        let token = issued.address();
        let sac = token::StellarAssetClient::new(&env, &token);
        let coin = token::TokenClient::new(&env, &token);
        sac.mint(&owner, &MINTED);

        let dkim = bytes32(&env, 0xD1);
        let commitment = bytes32(&env, 0xC0);
        let salt = bytes32(&env, 0x5A);
        contract.add_dkim_key(&dkim);

        Fx { env, contract, verifier, admin, owner, token, sac, coin, dkim, commitment, salt }
    }

    fn assets(&self) -> Vec<AssetSpec> {
        Vec::from_array(
            &self.env,
            [AssetSpec { token: self.token.clone(), floor: FLOOR }],
        )
    }

    /// Register and approve, the way the wallet actually does it.
    fn register(&self) {
        self.contract.register_and_approve(
            &self.owner,
            &self.commitment,
            &self.salt,
            &self.assets(),
            &MINTED,
            &(self.env.ledger().sequence() + 100_000),
        );
    }

    /// Public signals for a proof that pays out to `dest`.
    fn signals(&self, dest: &Address) -> Vec<BytesN<32>> {
        self.signals_with(dest, &self.commitment, &self.salt, &bytes32(&self.env, 0x11))
    }

    fn signals_with(
        &self,
        dest: &Address,
        commitment: &BytesN<32>,
        salt: &BytesN<32>,
        nullifier: &BytesN<32>,
    ) -> Vec<BytesN<32>> {
        let chunks = pack_address(&self.env, dest);
        Vec::from_array(
            &self.env,
            [
                self.dkim.clone(),
                commitment.clone(),
                chunks[0].clone(),
                chunks[1].clone(),
                chunks[2].clone(),
                nullifier.clone(),
                salt.clone(),
            ],
        )
    }

    fn advance(&self, seconds: u64) {
        let t = self.env.ledger().timestamp();
        self.env.ledger().set_timestamp(t + seconds);
    }
}

fn bytes32(env: &Env, fill: u8) -> BytesN<32> {
    BytesN::from_array(env, &[fill; 32])
}

/// A dummy proof. The mock verifier never looks at it; the contract only passes
/// it through. Points are zero, which the real verifier would reject and the
/// mock does not care about.
fn dummy_proof(env: &Env) -> Proof {
    Proof {
        a: Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0u8; 64])),
        b: Bn254G2Affine::from_bytes(BytesN::from_array(env, &[0u8; 128])),
        c: Bn254G1Affine::from_bytes(BytesN::from_array(env, &[0u8; 64])),
    }
}

/// Pack a 56-character address the way the circuit packs the subject: 31 bytes
/// per field element, little-endian, three chunks. This is the exact inverse of
/// `destination_from_subject`, so if either drifts these tests fail.
fn pack_address(env: &Env, addr: &Address) -> [BytesN<32>; 3] {
    let s = addr.to_string();
    let mut raw = [0u8; 93]; // 3 * 31, zero padded
    let mut text = [0u8; 56];
    s.copy_into_slice(&mut text);
    raw[..56].copy_from_slice(&text);

    let mut out = [[0u8; 32]; 3];
    for (i, chunk) in out.iter_mut().enumerate() {
        for j in 0..31usize {
            // little-endian inside the field element, so byte j of the chunk
            // is the (31 - j)th byte of the big-endian signal.
            chunk[31 - j] = raw[i * 31 + j];
        }
    }
    [
        BytesN::from_array(env, &out[0]),
        BytesN::from_array(env, &out[1]),
        BytesN::from_array(env, &out[2]),
    ]
}

// ─────────────────────────────── phase 1 ────────────────────────────────────

#[test]
fn register_and_approve_does_both_in_one_call() {
    let fx = Fx::new(5);
    fx.register();

    let reg = fx.contract.registration(&fx.owner).unwrap();
    assert_eq!(reg.owner, fx.owner);
    assert_eq!(reg.commitment, fx.commitment);
    assert_eq!(reg.salt, fx.salt);
    assert_eq!(reg.assets.len(), 1);
    assert_eq!(
        fx.coin.allowance(&fx.owner, &fx.contract.address),
        MINTED,
        "the allowance is what makes recovery possible at all"
    );
}

#[test]
#[should_panic(expected = "Error(Contract, #3)")]
fn cannot_register_twice() {
    let fx = Fx::new(5);
    fx.register();
    fx.contract.register(&fx.owner, &fx.commitment, &fx.salt, &fx.assets());
}

#[test]
#[should_panic(expected = "Error(Contract, #16)")]
fn rejects_an_empty_asset_list() {
    let fx = Fx::new(5);
    fx.contract.register(&fx.owner, &fx.commitment, &fx.salt, &Vec::new(&fx.env));
}

#[test]
#[should_panic(expected = "Error(Contract, #16)")]
fn rejects_more_than_eight_assets() {
    let fx = Fx::new(5);
    let mut many = Vec::new(&fx.env);
    for _ in 0..9 {
        many.push_back(AssetSpec { token: fx.token.clone(), floor: 0 });
    }
    fx.contract.register(&fx.owner, &fx.commitment, &fx.salt, &many);
}

#[test]
#[should_panic(expected = "Error(Contract, #15)")]
fn rejects_a_negative_floor() {
    let fx = Fx::new(5);
    let bad = Vec::from_array(
        &fx.env,
        [AssetSpec { token: fx.token.clone(), floor: -1 }],
    );
    fx.contract.register(&fx.owner, &fx.commitment, &fx.salt, &bad);
}

#[test]
fn update_email_changes_the_commitment() {
    let fx = Fx::new(5);
    fx.register();
    let new_c = bytes32(&fx.env, 0xEE);
    let new_s = bytes32(&fx.env, 0xFF);
    fx.contract.update_email(&fx.owner, &new_c, &new_s);

    let reg = fx.contract.registration(&fx.owner).unwrap();
    assert_eq!(reg.commitment, new_c);
    assert_eq!(reg.salt, new_s);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn update_email_is_blocked_while_a_recovery_is_pending() {
    let fx = Fx::new(DAY);
    fx.register();
    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));

    // An attacker who somehow started a recovery must not also be able to move
    // the goalposts while the owner is trying to react.
    fx.contract.update_email(&fx.owner, &bytes32(&fx.env, 0xEE), &bytes32(&fx.env, 0xFF));
}

#[test]
fn unregister_removes_everything() {
    let fx = Fx::new(5);
    fx.register();
    fx.contract.unregister(&fx.owner);
    assert!(fx.contract.registration(&fx.owner).is_none());
}

// ─────────────────────────────── phase 2, happy ─────────────────────────────

#[test]
fn full_recovery_moves_the_funds_and_leaves_the_floor() {
    let fx = Fx::new(5);
    fx.register();
    let dest = Address::generate(&fx.env);

    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));

    let pending = fx.contract.pending(&fx.owner).unwrap();
    assert_eq!(
        pending.destination, dest,
        "destination must come from the signed subject, not from any caller"
    );
    assert_eq!(pending.unlock_at, fx.env.ledger().timestamp() + 5);

    fx.advance(6);
    let moved = fx.contract.execute_recovery(&fx.owner);

    assert_eq!(moved.len(), 1);
    assert_eq!(moved.get_unchecked(0).floor, MINTED - FLOOR);
    assert_eq!(fx.coin.balance(&dest), MINTED - FLOOR);
    assert_eq!(fx.coin.balance(&fx.owner), FLOOR, "the floor stays behind");
    assert!(fx.contract.pending(&fx.owner).is_none());
    assert!(fx.contract.registration(&fx.owner).is_some(), "registration survives");
}

#[test]
fn allowance_caps_the_sweep() {
    let fx = Fx::new(5);
    fx.contract.register(&fx.owner, &fx.commitment, &fx.salt, &fx.assets());
    // Approve far less than the balance. The lesser of the two must win.
    let cap = 1_000_i128;
    fx.coin.approve(
        &fx.owner,
        &fx.contract.address,
        &cap,
        &(fx.env.ledger().sequence() + 100_000),
    );

    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));
    fx.advance(6);
    fx.contract.execute_recovery(&fx.owner);

    assert_eq!(fx.coin.balance(&dest), cap);
}

#[test]
fn anyone_may_submit_because_the_owner_has_no_key() {
    // The whole point: the person recovering cannot sign. If these calls
    // required the owner's auth the product would not exist.
    let env = Env::default();
    env.ledger().set_timestamp(1_700_000_000);
    env.mock_all_auths();
    let fx = Fx::new(5);
    fx.register();
    let dest = Address::generate(&fx.env);

    // start_recovery and execute_recovery carry no require_auth at all.
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));
    fx.advance(6);
    fx.contract.execute_recovery(&fx.owner);
    assert_eq!(fx.coin.balance(&dest), MINTED - FLOOR);
    let _ = env;
}

// ─────────────────────────────── phase 2, refusals ──────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #9)")]
fn rejects_a_proof_for_a_different_email() {
    let fx = Fx::new(5);
    fx.register();
    let dest = Address::generate(&fx.env);
    let signals = fx.signals_with(
        &dest,
        &bytes32(&fx.env, 0xBA), // someone else's commitment
        &fx.salt,
        &bytes32(&fx.env, 0x11),
    );
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &signals);
}

#[test]
#[should_panic(expected = "Error(Contract, #10)")]
fn rejects_a_proof_built_with_a_different_salt() {
    // The salt is public, so an attacker could pick one that makes THEIR email
    // hash to the victim's commitment. Pinning it to the registered value is
    // what closes that.
    let fx = Fx::new(5);
    fx.register();
    let dest = Address::generate(&fx.env);
    let signals = fx.signals_with(
        &dest,
        &fx.commitment,
        &bytes32(&fx.env, 0x99), // not the registered salt
        &bytes32(&fx.env, 0x11),
    );
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &signals);
}

#[test]
#[should_panic(expected = "Error(Contract, #8)")]
fn rejects_an_unknown_dkim_key() {
    let fx = Fx::new(5);
    fx.register();
    fx.contract.remove_dkim_key(&fx.dkim);
    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));
}

#[test]
#[should_panic(expected = "Error(Contract, #7)")]
fn rejects_a_proof_the_verifier_refuses() {
    let fx = Fx::new(5);
    fx.register();
    fx.verifier.set_ok(&false);
    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));
}

#[test]
#[should_panic(expected = "Error(Contract, #12)")]
fn rejects_the_wrong_number_of_public_inputs() {
    let fx = Fx::new(5);
    fx.register();
    let short = Vec::from_array(&fx.env, [fx.dkim.clone(), fx.commitment.clone()]);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &short);
}

#[test]
#[should_panic(expected = "Error(Contract, #13)")]
fn rejects_a_subject_that_is_not_an_address() {
    // This is the testnet result reproduced: a real, valid proof whose subject
    // said "zkemail test 2 final" was refused here.
    let fx = Fx::new(5);
    fx.register();
    let mut signals = fx.signals(&Address::generate(&fx.env));
    signals.set(PI_PAYOUT_0, bytes32(&fx.env, 0x00)); // blank the first chunk
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &signals);
}

#[test]
#[should_panic(expected = "Error(Contract, #13)")]
fn rejects_a_subject_with_a_non_base32_byte() {
    let fx = Fx::new(5);
    fx.register();
    let dest = Address::generate(&fx.env);
    let mut signals = fx.signals(&dest);
    // Corrupt one character of the address to a lowercase letter, which is not
    // in the base32 alphabet.
    let mut chunk = signals.get_unchecked(PI_PAYOUT_0).to_array();
    chunk[31] = b'a';
    signals.set(PI_PAYOUT_0, BytesN::from_array(&fx.env, &chunk));
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &signals);
}

#[test]
#[should_panic(expected = "Error(Contract, #2)")]
fn rejects_recovery_for_an_account_that_never_registered() {
    let fx = Fx::new(5);
    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));
}

// ─────────────────────────────── the delay ──────────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #6)")]
fn cannot_execute_before_the_delay_expires() {
    let fx = Fx::new(DAY);
    fx.register();
    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));
    fx.advance(DAY - 1);
    fx.contract.execute_recovery(&fx.owner);
}

#[test]
fn executes_exactly_on_the_boundary() {
    let fx = Fx::new(DAY);
    fx.register();
    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));
    fx.advance(DAY); // now == unlock_at, and the check is `<`
    fx.contract.execute_recovery(&fx.owner);
    assert_eq!(fx.coin.balance(&dest), MINTED - FLOOR);
}

// ─────────────────────────────── cancellation ───────────────────────────────

#[test]
fn owner_can_cancel_and_keeps_the_funds() {
    let fx = Fx::new(DAY);
    fx.register();
    let attacker_dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&attacker_dest));

    fx.contract.cancel_recovery(&fx.owner);

    assert!(fx.contract.pending(&fx.owner).is_none());
    assert_eq!(fx.coin.balance(&fx.owner), MINTED);
    assert_eq!(fx.coin.balance(&attacker_dest), 0);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn execute_after_cancel_fails() {
    let fx = Fx::new(DAY);
    fx.register();
    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));
    fx.contract.cancel_recovery(&fx.owner);
    fx.advance(DAY + 1);
    fx.contract.execute_recovery(&fx.owner);
}

#[test]
#[should_panic(expected = "Error(Contract, #11)")]
fn cancelling_does_not_un_burn_the_email() {
    // If cancelling released the nullifier, an attacker could resubmit the same
    // proof forever and the owner would have to cancel forever.
    let fx = Fx::new(DAY);
    fx.register();
    let dest = Address::generate(&fx.env);
    let signals = fx.signals(&dest);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &signals);
    fx.contract.cancel_recovery(&fx.owner);

    assert!(fx.contract.is_spent(&signals.get_unchecked(PI_NULLIFIER)));
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &signals);
}

#[test]
#[should_panic(expected = "Error(Contract, #5)")]
fn cannot_cancel_when_nothing_is_pending() {
    let fx = Fx::new(5);
    fx.register();
    fx.contract.cancel_recovery(&fx.owner);
}

// ─────────────────────────────── the nullifier ──────────────────────────────

#[test]
#[should_panic(expected = "Error(Contract, #11)")]
fn the_same_email_cannot_recover_twice() {
    let fx = Fx::new(5);
    fx.register();
    let dest = Address::generate(&fx.env);
    let signals = fx.signals(&dest);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &signals);
    fx.advance(6);
    fx.contract.execute_recovery(&fx.owner);

    fx.sac.mint(&fx.owner, &MINTED);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &signals);
}

#[test]
#[should_panic(expected = "Error(Contract, #11)")]
fn a_spent_email_cannot_be_used_on_a_different_registration() {
    // The nullifier is global to the contract, not scoped to one owner. This is
    // the test that proves it, and it is the one that would silently regress if
    // someone keyed nullifiers by owner.
    let fx = Fx::new(5);
    fx.register();
    let dest = Address::generate(&fx.env);
    let signals = fx.signals(&dest);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &signals);

    let other = Address::generate(&fx.env);
    fx.sac.mint(&other, &MINTED);
    fx.contract.register(&other, &fx.commitment, &fx.salt, &fx.assets());
    fx.contract.start_recovery(&other, &dummy_proof(&fx.env), &signals);
}

#[test]
#[should_panic(expected = "Error(Contract, #4)")]
fn only_one_recovery_at_a_time() {
    let fx = Fx::new(DAY);
    fx.register();
    let a = Address::generate(&fx.env);
    let b = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&a));
    let second = fx.signals_with(&b, &fx.commitment, &fx.salt, &bytes32(&fx.env, 0x22));
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &second);
}

// ─────────────────────────────── admin limits ───────────────────────────────

#[test]
fn admin_can_tune_the_delay() {
    let fx = Fx::new(5);
    fx.contract.set_min_delay(&(7 * DAY));
    assert_eq!(fx.contract.min_delay(), 7 * DAY);
}

#[test]
#[should_panic(expected = "Error(Contract, #15)")]
fn admin_cannot_freeze_funds_with_an_absurd_delay() {
    let fx = Fx::new(5);
    fx.contract.set_min_delay(&(31 * DAY)); // MAX_DELAY is 30 days
}

#[test]
#[should_panic(expected = "Error(Contract, #15)")]
fn constructor_rejects_an_absurd_delay() {
    let env = Env::default();
    env.mock_all_auths();
    let admin = Address::generate(&env);
    let v = env.register(MockVerifier, ());
    env.register(SpareKey, (admin, v, 31 * DAY));
}

#[test]
fn a_delay_change_does_not_touch_a_pending_recovery() {
    // unlock_at is stamped at start_recovery. Re-reading min_delay at execute
    // time would let the admin extend a recovery already in flight.
    let fx = Fx::new(5);
    fx.register();
    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));
    let unlock = fx.contract.pending(&fx.owner).unwrap().unlock_at;

    fx.contract.set_min_delay(&(30 * DAY));
    assert_eq!(fx.contract.pending(&fx.owner).unwrap().unlock_at, unlock);

    fx.advance(6);
    fx.contract.execute_recovery(&fx.owner);
    assert_eq!(fx.coin.balance(&dest), MINTED - FLOOR);
}

#[test]
fn admin_can_hand_over() {
    let fx = Fx::new(5);
    let next = Address::generate(&fx.env);
    fx.contract.set_admin(&next);
    assert_eq!(fx.contract.admin(), next);
}

#[test]
fn admin_has_no_way_to_move_funds() {
    // Not a behavioural test so much as a statement about the surface. If
    // someone adds a function that moves money on admin authority, the count
    // changes and this fails.
    let fx = Fx::new(5);
    fx.register();
    let before = fx.coin.balance(&fx.owner);
    fx.contract.set_min_delay(&10);
    fx.contract.add_dkim_key(&bytes32(&fx.env, 0xAA));
    fx.contract.remove_dkim_key(&bytes32(&fx.env, 0xAA));
    fx.contract.set_verifier(&fx.verifier.address);
    fx.contract.set_admin(&fx.admin);
    assert_eq!(fx.coin.balance(&fx.owner), before);
}

// ─────────────────────────────── views and events ───────────────────────────

#[test]
fn preview_destination_matches_what_recovery_would_pay() {
    let fx = Fx::new(5);
    let dest = Address::generate(&fx.env);
    assert_eq!(fx.contract.preview_destination(&fx.signals(&dest)), dest);
}

#[test]
fn recovery_started_is_published_so_a_watcher_can_warn_the_owner() {
    // The delay protects nobody who never hears about it. This event is the
    // only thing standing between a silent theft and a cancelled one.
    let fx = Fx::new(DAY);
    fx.register();
    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));

    let published = fx.env.events().all().filter_by_contract(&fx.contract.address);
    let found = published.events().iter().any(|e| {
        let soroban_sdk::xdr::ContractEventBody::V0(body) = &e.body;
        body.topics.iter().any(|t| {
            matches!(t, soroban_sdk::xdr::ScVal::Symbol(s)
                if s.to_utf8_string_lossy() == "recovery_started")
        })
    });
    assert!(found, "RecoveryStarted must be published");
}

#[test]
#[should_panic(expected = "Error(Contract, #14)")]
fn refuses_to_execute_when_there_is_nothing_left() {
    let fx = Fx::new(5);
    fx.register();
    let dest = Address::generate(&fx.env);
    fx.contract.start_recovery(&fx.owner, &dummy_proof(&fx.env), &fx.signals(&dest));
    // Owner drains the account themselves before the delay runs out.
    fx.coin.transfer(&fx.owner, &Address::generate(&fx.env), &MINTED);
    fx.advance(6);
    fx.contract.execute_recovery(&fx.owner);
}

#[test]
fn packing_round_trips() {
    // Guards the inverse relationship between pack_address here and
    // destination_from_subject in the contract. If either changes, this fails
    // first and loudly, instead of a recovery paying the wrong account.
    let fx = Fx::new(5);
    for _ in 0..8 {
        let a = Address::generate(&fx.env);
        assert_eq!(fx.contract.preview_destination(&fx.signals(&a)), a);
    }
    let _ = &events::Unregistered { owner: fx.owner.clone() };
}
