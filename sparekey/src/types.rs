use soroban_sdk::{
    contracterror, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    Address, BytesN, Vec,
};

// groth16 proof, laid out how the verifier wants it
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub a: Bn254G1Affine,
    pub b: Bn254G2Affine,
    pub c: Bn254G1Affine,
}

// where each value sits in the public signals. set by the circuit - change the
// circuit and this list changes too.
pub const PI_PUBKEY_HASH: u32 = 0;
pub const PI_COMMITMENT: u32 = 1;
pub const PI_PAYOUT_0: u32 = 2;
pub const PI_PAYOUT_CHUNKS: u32 = 3;
pub const PI_NULLIFIER: u32 = 5;
pub const PI_SALT: u32 = 6;
pub const PI_COUNT: u32 = 7;

// one asset recovery is allowed to move
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetSpec {
    // the SAC address
    pub token: Address,
    // how much to leave behind. for XLM this is the base reserve + some fee room,
    // sweeping to zero would hit the min-balance check and strand the account.
    pub floor: i128,
}

// what the owner stores while they still have their key
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registration {
    pub owner: Address,
    // poseidon(email packed, salt). the email itself never hits the chain.
    pub commitment: BytesN<32>,
    // public on purpose. stops one rainbow table unmasking everyone. not a secret,
    // and has to stay readable so the commitment can be recomputed.
    pub salt: BytesN<32>,
    pub assets: Vec<AssetSpec>,
    pub registered_at: u64,
}

// a proven recovery waiting out its delay
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pending {
    // where funds go. from the signed subject, never the caller.
    pub destination: Address,
    pub unlock_at: u64,
    pub nullifier: BytesN<32>,
    pub started_at: u64,
}

#[contracttype]
pub enum DataKey {
    Admin,
    // the groth16 verifier
    Verifier,
    // seconds between proof and payout, the cancel window. admin sets it.
    MinDelay,
    // allowed dkim key hashes (as the circuit outputs them)
    DkimKey(BytesN<32>),
    Reg(Address),
    Pending(Address),
    // spent emails. global, so one email can't be reused even on a different
    // registration.
    Nullifier(BytesN<32>),
}

#[contracterror]
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u32)]
pub enum Error {
    AlreadyInitialized = 1,
    NotRegistered = 2,
    AlreadyRegistered = 3,
    RecoveryInProgress = 4,
    NoRecoveryPending = 5,
    StillLocked = 6,
    BadProof = 7,
    UnknownDkimKey = 8,
    WrongCommitment = 9,
    WrongSalt = 10,
    NullifierUsed = 11,
    BadPublicInputs = 12,
    BadDestination = 13,
    NothingToRecover = 14,
    InvalidParams = 15,
    TooManyAssets = 16,
}
