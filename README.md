# Ghost Wallet

An iPhone wallet for Ghost.

> **Experimental and unaudited.** Ghost Wallet is under construction. Do not use
> it with funds you cannot afford to lose.

## What it does

- **Quantum-safe accounts.** Create or restore a Ghost account, see the balance,
  send, and receive to fresh addresses. Accounts use lattice-based signatures
  with a hash-based rescue key. No elliptic-curve key exists anywhere in the app.
- **Vanish, Summon and Claim,** proved on the phone itself.
- **Phantom Keys on a card.** Write a Phantom Key to a blank NTAG 424 DNA card,
  then tap the card later to Summon or Claim. The card is never the only
  backup: every Phantom Key is also shown as words.

## How it works

- Secrets (account words, Phantom Keys, card keys and PINs) stay in native code
  and are never logged.
- There is no backend and no relayer. The app talks only to the Ghost node
  endpoint you choose, and checks the chain's headers itself instead of trusting
  that endpoint.
- The proving and key code is Ghost's own Rust library, built for iOS.

## Licence

The project's own code is licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE)), or
- MIT license ([LICENSE-MIT](LICENSE-MIT)),

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in the work by you, as defined in the Apache-2.0
licence, shall be dual licensed as above, without any additional terms or
conditions.
