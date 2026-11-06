//! Why a flow stopped. No variant carries a key, a PIN or any other secret.

use core::fmt;

/// Everything that can stop a Seal flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SealError {
    /// The card left the field (or the phone's relay went away) before its
    /// answer came back. The flow can be run again from the start.
    Dropped,
    /// The chip answered a status other than the one the command expects.
    Chip {
        /// The command that was refused.
        command: u8,
        /// The status words.
        sw1: u8,
        /// The status words.
        sw2: u8,
    },
    /// An answer whose length, MAC, padding or proof of key is wrong.
    Integrity(&'static str),
    /// A command would not fit a short APDU, or a frame would be longer
    /// than [`crate::record::FRAME_BYTES`].
    TooLong,
    /// The card's keys are not the ones the Seal derives for it (a card
    /// that was never set up, or another card answering for this UID).
    UnknownKeys,
    /// The card's record file is not set up as the Seal needs it.
    NotSetUp,
    /// A frame of the card record fails its check (a write that never
    /// finished, or bytes that are not a record).
    TornRecord,
    /// What was read back is not what was written.
    VerifyFailed,
    /// The card is not in a state that allows this flow.
    WrongState(crate::record::CardState),
    /// A Fill is already written on this card and waits for its payment.
    FillPending,
    /// The chain check has not seen the payment yet.
    NotPaid,
    /// The chain check saw a payment that is not exactly this coin.
    PaymentMismatch,
    /// The coin is paid exactly but its block is not yet deep enough to be
    /// settled: the card is still filling.
    NotSettled,
    /// The coin's spend marker is used: the coin is spent.
    CoinSpent,
    /// The chain status could not be checked right now: a node could not be
    /// reached, or the nodes do not agree.
    CantCheckNow,
    /// The card has an Open PIN and none was given.
    PinRequired,
    /// The Open PIN was wrong; this many tries are left.
    WrongPin {
        /// Tries left before the card refuses every Open.
        tries_left: u8,
    },
    /// The Open PIN's tries are used up.
    PinLocked,
    /// A PIN that is not 4 to 12 digits.
    BadPin,
    /// The phone key is not an ML-KEM-768 encapsulation key.
    BadPhoneKey,
    /// An Open is pending for this card and was started for another phone key.
    PhoneKeyMismatch,
    /// The card says an Open began, but the Seal holds no journal of it.
    JournalMissing,
    /// The journal store refused or lost an entry, or an entry fails its check.
    Journal(&'static str),
    /// A Phantom Key that is empty or longer than the key slot.
    BadPhantomKey,
    /// The Phantom Key maker failed.
    KeyMaker(&'static str),
    /// The amount is zero.
    BadAmount,
    /// The random source failed.
    Random,
    /// A release package that does not open with this phone key.
    BadRelease,
    /// The card's UID is not in the card registry: the card setup never
    /// finished it, so the Seal does not touch it.
    NotAGhostCard,
    /// The card registry refused or lost an entry, or an entry is malformed.
    Registry(&'static str),
}

impl fmt::Display for SealError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SealError::Dropped => f.write_str("the card connection dropped"),
            SealError::Chip { command, sw1, sw2 } => {
                write!(f, "command {command:02X} answered {sw1:02X}{sw2:02X}")
            }
            SealError::Integrity(what) => write!(f, "integrity: {what}"),
            SealError::TooLong => f.write_str("a command or frame is too long"),
            SealError::UnknownKeys => f.write_str("the card does not hold the keys the Seal derives for it"),
            SealError::NotSetUp => f.write_str("the card's record file is not set up"),
            SealError::TornRecord => f.write_str("the card record fails its check"),
            SealError::VerifyFailed => f.write_str("the read-back differs from what was written"),
            SealError::WrongState(state) => write!(f, "the card is {state:?}"),
            SealError::FillPending => f.write_str("a Fill on this card waits for its payment"),
            SealError::NotPaid => f.write_str("the payment is not on the chain yet"),
            SealError::PaymentMismatch => f.write_str("the payment on the chain is not exactly this coin"),
            SealError::NotSettled => f.write_str("the card is filling, waiting for its payment to settle"),
            SealError::CoinSpent => f.write_str("the card's coin is spent"),
            SealError::CantCheckNow => f.write_str("the chain cannot be checked right now"),
            SealError::PinRequired => f.write_str("this card needs its Open PIN"),
            SealError::WrongPin { tries_left } => write!(f, "wrong PIN, {tries_left} tries left"),
            SealError::PinLocked => f.write_str("the Open PIN is locked"),
            SealError::BadPin => f.write_str("a PIN is 4 to 12 digits"),
            SealError::BadPhoneKey => f.write_str("the phone key is not an ML-KEM-768 key"),
            SealError::PhoneKeyMismatch => f.write_str("the pending Open is bound to another phone key"),
            SealError::JournalMissing => f.write_str("the card shows an Open the Seal has no journal of"),
            SealError::Journal(what) => write!(f, "journal: {what}"),
            SealError::BadPhantomKey => f.write_str("a Phantom Key must be 1 to 64 bytes"),
            SealError::KeyMaker(what) => write!(f, "Phantom Key maker: {what}"),
            SealError::BadAmount => f.write_str("the amount must be more than zero"),
            SealError::Random => f.write_str("the random source failed"),
            SealError::BadRelease => f.write_str("the release package does not open"),
            SealError::NotAGhostCard => f.write_str("Not a Ghost card"),
            SealError::Registry(what) => write!(f, "card registry: {what}"),
        }
    }
}

impl std::error::Error for SealError {}
