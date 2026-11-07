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

/// A new Phantom Key, the public commit data of its coin and the coin's
/// spend marker.
pub struct MadeKey {
    /// The key; wiped when dropped.
    pub key: PhantomKey,
    /// The coin's commit data (public: the Vanish carries it).
    pub commit_data: Vec<u8>,
    /// The coin's spend marker, for the chain check's unspent test. It is
    /// public once the coin is spent and tells nothing before.
    pub spend_marker: [u8; 32],
}

/// The wallet core's Phantom Key derivation: makes a fresh Phantom Key, the
/// commit data of its coin of `amount_wei` and that coin's spend marker, from
/// the Seal's random source.
/// The Seal's maker is `key_maker::CoreKeyMaker`: the wallet core's key
/// bytes and its coin commit number 0, the coin a card Vanish pays. Tests
/// may use a stand-in.
pub trait PhantomKeyMaker {
    /// Makes a key and its coin.
    fn make(&mut self, amount_wei: u128, random: &mut dyn SealRandom) -> Result<MadeKey, SealError>;
}

/// The bytes [`DrawnRandom::draw`] draws: enough for an ML-KEM-768
/// encapsulation, which draws 32.
const DRAWN_BYTES: usize = 64;

/// Random bytes drawn from a [`SealRandom`] before a call that needs an
/// infallible `rand_core` generator, held in a buffer wiped when dropped.
///
/// [`DrawnRandom::draw`] draws 64 bytes for the ML-KEM encapsulation, and
/// asking it for more is a bug in the caller and panics.
/// [`DrawnRandom::draw_exact`] draws as many as its caller counted: asking
/// it for more never panics and never hands out a byte that was not drawn
/// in its place; [`DrawnRandom::finish`] then says
/// [`SealError::KeyMaker`], and the caller throws away what it made.
pub(crate) struct DrawnRandom {
    bytes: zeroize::Zeroizing<Vec<u8>>,
    used: usize,
    /// Asking for more than was drawn panics (the 64-byte draw).
    strict: bool,
    /// More was asked for than was drawn.
    overdrawn: bool,
}

impl DrawnRandom {
    /// Draws 64 bytes.
    pub(crate) fn draw(random: &mut dyn SealRandom) -> Result<DrawnRandom, SealError> {
        let mut drawn = DrawnRandom::draw_exact(random, DRAWN_BYTES)?;
        drawn.strict = true;
        Ok(drawn)
    }

    /// Draws exactly `length` bytes, in one call of `random`.
    pub(crate) fn draw_exact(random: &mut dyn SealRandom, length: usize) -> Result<DrawnRandom, SealError> {
        let mut bytes = zeroize::Zeroizing::new(vec![0u8; length]);
        random.fill(&mut bytes[..])?;
        Ok(DrawnRandom { bytes, used: 0, strict: false, overdrawn: false })
    }

    /// The next `length` drawn bytes, or [`SealError::KeyMaker`] when fewer
    /// are left.
    pub(crate) fn take(&mut self, length: usize) -> Result<&[u8], SealError> {
        let end = self.used.checked_add(length).filter(|end| *end <= self.bytes.len()).ok_or_else(|| {
            self.overdrawn = true;
            OVERDRAWN
        })?;
        let start = self.used;
        self.used = end;
        Ok(&self.bytes[start..end])
    }

    /// [`SealError::KeyMaker`] when more was asked for than was drawn.
    pub(crate) fn finish(&self) -> Result<(), SealError> {
        if self.overdrawn { Err(OVERDRAWN) } else { Ok(()) }
    }
}

/// More random bytes were asked for than were drawn.
const OVERDRAWN: SealError = SealError::KeyMaker("more random bytes were asked for than were drawn");

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
        let strict = self.strict;
        match self.take(dst.len()) {
            Ok(drawn) => dst.copy_from_slice(drawn),
            Err(_) => {
                assert!(!strict, "more random bytes were asked for than were drawn");
                // Never a byte that was not drawn: the filler is all ones, and
                // whatever was made with it is thrown away (`finish`).
                dst.fill(0xff);
            }
        }
        Ok(())
    }
}

impl rand_core::TryCryptoRng for DrawnRandom {}

#[cfg(test)]
mod tests {
    use rand_core::TryRng;

    use super::*;

    struct Counter(u8);

    impl SealRandom for Counter {
        fn fill(&mut self, out: &mut [u8]) -> Result<(), SealError> {
            for byte in out {
                self.0 = self.0.wrapping_add(1);
                *byte = self.0;
            }
            Ok(())
        }
    }

    #[test]
    fn a_draw_past_the_buffer_is_a_key_maker_error_not_a_panic() {
        let mut drawn = DrawnRandom::draw_exact(&mut Counter(0), 4).unwrap();
        let mut first = [0u8; 3];
        drawn.try_fill_bytes(&mut first).unwrap();
        assert_eq!(first, [1, 2, 3]);
        assert_eq!(drawn.finish(), Ok(()));
        let mut past = [0u8; 2];
        drawn.try_fill_bytes(&mut past).unwrap();
        assert_eq!(past, [0xff, 0xff], "no byte that was not drawn, and no zero");
        assert!(matches!(drawn.finish(), Err(SealError::KeyMaker(_))));
        assert!(matches!(drawn.take(2), Err(SealError::KeyMaker(_))));
        // A draw that still fits does not clear the failure.
        assert_eq!(drawn.take(1).map(<[u8]>::to_vec), Ok(vec![4]));
        assert!(matches!(drawn.finish(), Err(SealError::KeyMaker(_))));
    }

    #[test]
    #[should_panic(expected = "more random bytes were asked for than were drawn")]
    fn the_64_byte_draw_still_panics_past_its_buffer() {
        let mut drawn = DrawnRandom::draw(&mut Counter(0)).unwrap();
        let mut out = [0u8; 65];
        let _ = drawn.try_fill_bytes(&mut out);
    }
}
