//! The Seal's Phantom Key maker: [`CoreKeyMaker`], the wallet core's own
//! derivation, run inside the Seal for a Fill.
//!
//! For a Fill of `amount_wei` it:
//!
//! 1. counts the random bytes the core's `vanish_commit_with` draws for a
//!    coin (the salt and the note's nonce), by making a throwaway coin of a
//!    fixed public key with a source that only counts;
//! 2. draws the key's 32 secret bytes and that count, in one call of the
//!    [`SealRandom`] it is handed (the enclave's `getrandom`), into a buffer
//!    wiped when dropped. It never calls the operating system itself;
//! 3. makes the key bytes, the format code `0x20` then the 32 secret bytes
//!    (`docs/sealed-card.md`: what the key slot and an Open release hold),
//!    and the core's key from them with `phantom_key_from_bytes`, the
//!    function the phone uses on a release;
//! 4. makes the key's coin commit number 0 with the core's
//!    `vanish_commit_with` (the empty rule, a version-3 note, 430 bytes of
//!    commit data), drawing the salt and the nonce from the same buffer;
//! 5. finds that coin again with the core's restore (`commit_leaf`, then
//!    `unspent_coin`), as the phone's lookup will, and takes its spend marker
//!    from it: the core's own marker, not a copy of its code.
//!
//! No elliptic-curve key is made or used: the coin is Ghost's hash
//! commitment and its note is sealed under a key the core derives from the
//! Phantom Key by hashing. The key is never logged, formatted or made into
//! words; it leaves this module only in the [`MadeKey`] the Seal writes to
//! the card, under EV2 secure messaging, and then wipes. If the random
//! source fails, nothing is made.

use ghost_wallet_core::seal_open::{KEY_FORMAT_CODE, KEY_SECRET_BYTES, phantom_key_from_bytes};
use ghost_wallet_core::vanish::{VanishError, tree_leaves, unspent_coin};
use ghost_wallet_core::{commit_leaf, vanish_commit_with};

use crate::error::SealError;
use crate::secrets::PhantomKey;
use crate::traits::{DrawnRandom, MadeKey, PhantomKeyMaker, SealRandom};

/// The wallet core's Phantom Key derivation, for the coins of one chain.
pub struct CoreKeyMaker {
    chain_id: u64,
}

impl CoreKeyMaker {
    /// A maker of keys whose coins are on chain `chain_id`: the chain the
    /// note of each coin is sealed for, and the one the chain check follows.
    pub fn new(chain_id: u64) -> CoreKeyMaker {
        CoreKeyMaker { chain_id }
    }

    /// The chain the coins are made for.
    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }
}

impl PhantomKeyMaker for CoreKeyMaker {
    fn make(&mut self, amount_wei: u128, random: &mut dyn SealRandom) -> Result<MadeKey, SealError> {
        let commit_bytes = commit_draw(self.chain_id, amount_wei)?;
        let mut drawn = DrawnRandom::draw_exact(random, KEY_SECRET_BYTES + commit_bytes)?;

        let mut bytes = Vec::with_capacity(1 + KEY_SECRET_BYTES);
        bytes.push(KEY_FORMAT_CODE);
        bytes.extend_from_slice(drawn.take(KEY_SECRET_BYTES)?);
        // Wiped when dropped, from here on.
        let key = PhantomKey::new(bytes)?;
        let core_key = phantom_key_from_bytes(key.expose_secret())
            .map_err(|_| SealError::KeyMaker("the core refused the key bytes"))?;

        let commit = vanish_commit_with(&core_key, self.chain_id, amount_wei, &mut drawn).map_err(refused)?;
        drawn.finish()?;
        drop(drawn);

        // The coin, found by the key as the phone will find it.
        let leaf = commit_leaf(commit.commit_data.clone(), amount_wei.to_string()).map_err(refused)?;
        if leaf.commitment != commit.commitment {
            return Err(SealError::KeyMaker("the coin's leaf is not the one made"));
        }
        let leaves = tree_leaves(&[leaf]).map_err(refused)?;
        let coin = unspent_coin(&core_key, self.chain_id, &leaves, &[])
            .map_err(|_| SealError::KeyMaker("the key does not find its own coin"))?;
        let same_leaf = coin.commitment.as_bytes()[..] == commit.commitment[..];
        if coin.number != 0 || coin.amount.wei() != amount_wei || !same_leaf {
            return Err(SealError::KeyMaker("the key finds another coin than the one made"));
        }
        Ok(MadeKey { key, commit_data: commit.commit_data, spend_marker: *coin.marker.as_bytes() })
    }
}

/// How many random bytes `vanish_commit_with` draws for a coin of
/// `amount_wei` on `chain_id`: counted on a throwaway coin of a fixed public
/// key, which is then dropped. Nothing is drawn from the Seal's source.
fn commit_draw(chain_id: u64, amount_wei: u128) -> Result<usize, SealError> {
    let mut throwaway = [0u8; 1 + KEY_SECRET_BYTES];
    throwaway[0] = KEY_FORMAT_CODE;
    let key = phantom_key_from_bytes(&throwaway).map_err(|_| SealError::KeyMaker("the core refused the key bytes"))?;
    let mut counting = Counting(0);
    vanish_commit_with(&key, chain_id, amount_wei, &mut counting).map_err(refused)?;
    Ok(counting.0)
}

fn refused(error: VanishError) -> SealError {
    match error {
        VanishError::Amount { .. } => SealError::BadAmount,
        _ => SealError::KeyMaker("the core could not make the coin"),
    }
}

/// A source that counts what is asked of it. What it gives (zeros) goes
/// only into the throwaway coin of [`commit_draw`].
struct Counting(usize);

impl rand_core::TryRng for Counting {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.0 += 4;
        Ok(0)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.0 += 8;
        Ok(0)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.0 += dst.len();
        dst.fill(0);
        Ok(())
    }
}

impl rand_core::TryCryptoRng for Counting {}
