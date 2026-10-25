# SwiftEx Recovery Contracts

Soroban smart contracts for SwiftEx's email-based wallet recovery. A user registers
a commitment to their email address while they still control their wallet. If they
lose their device, they email their new Stellar address to a relayer; a zero-knowledge
proof shows a mail provider (via DKIM) signed that email from the committed address,
and the contract releases the account's assets to the address named in the signed
subject. No key is ever held by anyone, and the destination comes out of the signed
email — not from whoever submits the transaction — so a relayer can delay a recovery
but can never redirect it.

## Contracts

### `sparekey`
The recovery vault. Holds the email commitment and a standing allowance, verifies the
proof through the verifier below, and runs a cancellable timelock before funds move.

- `register` / `register_and_approve` — store the commitment + salt and grant the
  allowance (one signature with `register_and_approve`).
- `start_recovery` — permissionless; checks the DKIM key against an allowlist, the
  commitment and salt against what was registered, the nullifier against replay, then
  verifies the proof and starts the timelock. Destination is decoded from the signed
  subject.
- `cancel_recovery` — the owner, if they still hold their key, cancels within the delay.
- `execute_recovery` — permissionless after the delay; sweeps each asset down to its
  floor to the destination.
- Admin can add/remove DKIM keys, set the verifier and the delay. Admin cannot move
  funds, start a recovery, or alter a registration.

### `zkverifier`
A Groth16 verifier over BN254, using Soroban's native pairing host functions. The
verifying key is baked in at build time. `verify_proof` rejects non-canonical public
inputs and runs the pairing check.

## Build

```
stellar contract build
```

Outputs to `target/wasm32v1-none/release/`.


`sparekey` ships with a full test suite covering every failure path (bad proof,
unknown DKIM key, wrong commitment, wrong salt, reused nullifier, malformed
destination, the delay boundary, cancellation, and the sweep allowance cap) against a
mock verifier.

## How recovery works

```
register (once, with your key)      email commitment + salt stored on-chain
        │
   ... lose your device ...
        │
email new address to relayer        subject = new Stellar address, DKIM-signed
        │
zk proof + start_recovery           proof that a DKIM-signed email from the committed
        │                           address named that destination; timelock begins
        │
   ... cancel window ...            owner can cancel if the key is still theirs
        │
execute_recovery                    assets move to the signed destination
```

## Status

Testnet. Not audited. The Groth16 trusted setup is a development ceremony and must be
replaced before mainnet. The minimum recovery delay and DKIM key allowlist are set per
deployment.

## License

Apache-2.0
