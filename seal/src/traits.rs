//! What the Seal is given from outside, each a trait a test replaces: its
//! random source, its clock, the card transport (one APDU in, one answer
//! out, relayed by the phone), the chain check and the wallet core's Phantom
//! Key derivation. Nothing here opens a socket or reads a file.

use crate::card_keys::CardUid;
use crate::error::SealError;
use crate::secrets::PhantomKey;

/// The Seal's random source.
pub trait SealRandom {
    /// Fills `out` with random bytes.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError>;
}

/// The operating system's random source.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemRandom;

impl SealRandom for SystemRandom {
    fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
        getrandom::fill(out).map_err(|_| SealError::Random)
    }
}

/// The Seal's clock, for the expiry of its answers.
pub trait Clock {
    /// Seconds since the Unix epoch.
    fn now_unix(&self) -> u64;
}

/// The system clock.
#[derive(Debug, Default, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_unix(&self) -> u64 {
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
    }
}

/// The connection to the card went away before its answer came back.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dropped;

/// The card, as the phone relays it: one raw APDU in, one raw answer out.
pub trait CardTransport {
    /// Sends `apdu` and returns the card's raw answer (data and status words).
    fn transceive(&mut self, apdu: &[u8]) -> Result<Vec<u8>, Dropped>;
}

/// What a Fill's chain check is asked: is this exact coin paid?
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CoinClaim {
    /// The card.
    pub uid: CardUid,
    /// SHA3-256 of the coin's commit data.
    pub coin: [u8; 32],
    /// The amount the coin must hold, in wei.
    pub amount_wei: u128,
}

/// What the chain check found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PaymentVerdict {
    /// A final Vanish with exactly this commit data and exactly this amount.
    Paid,
    /// Nothing final yet.
    NotYet,
    /// A payment that is not exactly this coin and amount.
    Mismatch,
}

/// The chain check: whether a coin is paid exactly and final. Built in its
/// own crate; the Seal only asks it.
pub trait ChainCheck {
    /// Checks `claim` against the chain.
    fn confirm_payment(&self, claim: &CoinClaim) -> PaymentVerdict;
}

/// A new Phantom Key and the public commit data of its coin.
pub struct MadeKey {
    /// The key; wiped when dropped.
    pub key: PhantomKey,
    /// The coin's commit data (public: the Vanish carries it).
    pub commit_data: Vec<u8>,
}

/// The wallet core's Phantom Key derivation: makes a fresh Phantom Key and the
/// commit data of its coin of `amount_wei`, from the Seal's random source.
/// The enclave build backs it with the same calls the app's card Vanish
/// uses (Ghost's client library: a new card-only key and its coin commit
/// number 0); tests use a stand-in.
pub trait PhantomKeyMaker {
    /// Makes a key and its coin.
    fn make(&mut self, amount_wei: u128, random: &mut dyn SealRandom) -> Result<MadeKey, SealError>;
}

/// Random bytes drawn from a [`SealRandom`] before a call that needs an
/// infallible `rand_core` generator (the ML-KEM encapsulation draws 32).
/// Asking for more than was drawn is a bug in the caller and panics.
pub(crate) struct DrawnRandom {
    bytes: zeroize::Zeroizing<[u8; 64]>,
    used: usize,
}

impl DrawnRandom {
    pub(crate) fn draw(random: &mut dyn SealRandom) -> Result<DrawnRandom, SealError> {
        let mut bytes = zeroize::Zeroizing::new([0u8; 64]);
        random.fill(&mut bytes[..])?;
        Ok(DrawnRandom { bytes, used: 0 })
    }
}

impl rand_core::TryRng for DrawnRandom {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        let mut bytes = [0u8; 4];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u32::from_le_bytes(bytes))
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        let mut bytes = [0u8; 8];
        self.try_fill_bytes(&mut bytes)?;
        Ok(u64::from_le_bytes(bytes))
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        let end = self.used + dst.len();
        assert!(end <= self.bytes.len(), "more random bytes were asked for than were drawn");
        dst.copy_from_slice(&self.bytes[self.used..end]);
        self.used = end;
        Ok(())
    }
}

impl rand_core::TryCryptoRng for DrawnRandom {}
