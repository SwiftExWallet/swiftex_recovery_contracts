use soroban_sdk::{
    contracterror, contracttype,
    crypto::bn254::{Bn254G1Affine, Bn254G2Affine},
    Address, BytesN, Vec,
};

/// A Groth16 proof, laid out exactly as the generated verifier expects it.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Proof {
    pub a: Bn254G1Affine,
    pub b: Bn254G2Affine,
    pub c: Bn254G1Affine,
}

/// Position of each value in the circuit's public signals. Fixed by
/// legacy_claim.circom; changing the circuit changes this list.
pub const PI_PUBKEY_HASH: u32 = 0;
pub const PI_COMMITMENT: u32 = 1;
pub const PI_PAYOUT_0: u32 = 2;
pub const PI_PAYOUT_CHUNKS: u32 = 3;
pub const PI_NULLIFIER: u32 = 5;
pub const PI_SALT: u32 = 6;
pub const PI_COUNT: u32 = 7;

/// One asset the recovery is allowed to sweep.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AssetSpec {
    /// Stellar Asset Contract address.
    pub token: Address,
    /// Amount left behind in the owner's account. For native XLM this covers
    /// the base reserve plus fee headroom: sweeping to zero fails the
    /// min-balance check outright and would strand everything.
    pub floor: i128,
}

/// What the owner registers while they still have their key.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registration {
    pub owner: Address,
    /// Poseidon(sender address packed, salt). The email never touches the chain.
    pub commitment: BytesN<32>,
    /// Public by design. Defeats one rainbow table unmasking every user; it is
    /// not a secret and must stay readable so the commitment can be recomputed.
    pub salt: BytesN<32>,
    pub assets: Vec<AssetSpec>,
    pub registered_at: u64,
}

/// A recovery that has been proven and is waiting out its delay.
#[contracttype]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Pending {
    /// Where funds go. Taken from the signed Subject, never from a caller.
    pub destination: Address,
    pub unlock_at: u64,
    pub nullifier: BytesN<32>,
    pub started_at: u64,
}

#[contracttype]
pub enum DataKey {
    Admin,
    /// Groth16 verifier for the claim circuit.
    Verifier,
    /// Seconds between a proven recovery and payout, during which the owner
    /// can cancel. Admin-set.
    MinDelay,
    /// Accepted DKIM public key hashes, as published by the circuit.
    DkimKey(BytesN<32>),
    Reg(Address),
    Pending(Address),
    /// Spent emails. Global to this contract, so one email can never be used
    /// twice even across different registrations.
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
