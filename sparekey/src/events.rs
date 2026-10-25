//! Public event schema. Published so a third party can run the relayer and the
//! notifier without us: the claim that recovery survives SwiftEx disappearing
//! is only true if these are documented and stable.

use soroban_sdk::{contractevent, Address, BytesN};

#[contractevent(topics = ["sparekey", "registered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Registered {
    #[topic]
    pub owner: Address,
    pub commitment: BytesN<32>,
    pub salt: BytesN<32>,
}

#[contractevent(topics = ["sparekey", "email_changed"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailChanged {
    #[topic]
    pub owner: Address,
    pub commitment: BytesN<32>,
}

#[contractevent(topics = ["sparekey", "unregistered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Unregistered {
    #[topic]
    pub owner: Address,
}

/// The signal an owner must react to. A notifier watches this and warns them,
/// because the delay only protects someone who hears about it.
#[contractevent(topics = ["sparekey", "recovery_started"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryStarted {
    #[topic]
    pub owner: Address,
    #[topic]
    pub destination: Address,
    pub unlock_at: u64,
}

#[contractevent(topics = ["sparekey", "recovery_cancelled"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RecoveryCancelled {
    #[topic]
    pub owner: Address,
    pub destination: Address,
}

#[contractevent(topics = ["sparekey", "recovered"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Recovered {
    #[topic]
    pub owner: Address,
    #[topic]
    pub destination: Address,
    pub moved: soroban_sdk::Vec<crate::types::AssetSpec>,
}

#[contractevent(topics = ["sparekey", "admin"])]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminChange {
    pub what: soroban_sdk::Symbol,
    pub value: i128,
}
