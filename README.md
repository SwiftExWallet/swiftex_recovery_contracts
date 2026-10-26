# SwiftEx Recovery Contracts

Soroban smart contracts for SwiftEx's email-based wallet recovery. A user registers
a commitment to their email address while they still control their wallet. If they
lose their device, they email their new Stellar address to a relayer; a zero-knowledge
proof shows a mail provider (via DKIM) signed that email from the committed address,
and the contract releases the account's assets to the address named in the signed
subject. No key is ever held by anyone, and the destination comes out of the signed
email — not from whoever submits the transaction — so a relayer can delay a recovery
but can never redirect it.

## HackMeridian 2026

This repo is the on-chain half of SwiftEx email recovery. The full build spans four repos:

- **Contracts** (this repo): the Soroban recovery vault and the zkEmail Groth16 verifier.
- **Backend**: https://github.com/SwiftExWallet/swift-ex-proxy-server/tree/feature/hackmeridian
- **Mobile**: https://github.com/SwiftExWallet/SwiftEx/tree/feature/zk-email-recovery
- **Web**: https://github.com/SwiftExWallet/swiftexchange-web/tree/feature/zk-email-recovery

### Try it (testnet)

It all runs on Stellar testnet. Connect and sign with the SwiftEx wallet or with Freighter.
Need test XLM- Use the "Fund Wallet" (on Freighter) button in the app. You can also grab the SwiftEx testnet
APK (Android, optional): https://drive.google.com/drive/folders/14c11n8KVfsL2e5G6Op6ryseXIm2OZE_u

**Register a recovery email** at https://testnet.swiftexchange.io/recovery?tab=register

1. Open the page and connect your wallet (SwiftEx or Freighter).
2. Go to "Register Guardian" and type your recovery email twice. Paste is off on purpose, to stop typos.
3. Pick what to protect: XLM only, or both XLM and USDC.
4. Sign the transaction. One signature stores a hash of your email on-chain and sets the recovery allowance. 

**Recover to a new wallet** at https://testnet.swiftexchange.io/recovery?tab=recover

1. Go to "Recover Funds". Enter the lost wallet address, your recovery email, and the new destination wallet.
2. From that same email, send a mail to claim@swiftexwallet.in with your new Stellar address as the subject line.
3. The relayer checks the email's DKIM signature and submits the zk proof on-chain for you.
4. After the safety delay (short on testnet, days on mainnet) the funds move to your new wallet. The original owner can cancel during the delay if they still hold their key.

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

## Tests

```
cargo test
```

38 tests on `sparekey`, run against a mock verifier so we can force both pass and
fail. They cover the happy path and every way recovery should be rejected:

- registration: can't register twice, empty/too-many assets, negative floor,
  update-email, unregister, update blocked while a recovery is pending
- proofs: wrong commitment, wrong salt, unknown DKIM key, bad proof, wrong number
  of public inputs, subject that isn't an address, non-base32 bytes in the subject
- replay: same email can't recover twice, a spent email can't be used on another
  registration, cancelling does not un-burn the email
- timelock: can't execute before the delay, executes right on the boundary, owner
  can cancel and keep the funds, execute-after-cancel fails
- sweep: moves the funds and leaves the floor, allowance caps the sweep, nothing to
  recover when everything's at the floor
- admin: can tune the delay, can't freeze funds with an absurd delay, can't move
  funds, hand-over works
- `pack_address` in the tests is the exact inverse of the on-chain unpacking, so if
  either drifts the round-trip test fails first

## Deployments

Testnet (Soroban).

| contract | id |
|---|---|
| SpareKey | [`CDT5MXYHAZK6YPTWFBKPECHGPCBQFINME6WJCONXCT73RKJRDIJ2HYJK`](https://stellar.expert/explorer/testnet/contract/CDT5MXYHAZK6YPTWFBKPECHGPCBQFINME6WJCONXCT73RKJRDIJ2HYJK) |
| zkVerifier | [`CDK5O355WO7MJPAB2PLRLKI4BUB6WH7LGUDEW4WBJYIGTVHK3PJVEKTZ`](https://stellar.expert/explorer/testnet/contract/CDK5O355WO7MJPAB2PLRLKI4BUB6WH7LGUDEW4WBJYIGTVHK3PJVEKTZ) |

Network passphrase `Test SDF Network ; September 2015`, RPC
`https://soroban-testnet.stellar.org`.

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
