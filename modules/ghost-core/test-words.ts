// Fixed, public test words: Ghost's counting-bytes test seed (bytes 0 to 31).
// They are the only words that ever reach JavaScript, and they guard nothing.
// core/tests/address.rs checks that they match Ghost's client crate.
export const TEST_WORDS =
  'abandon amount liar amount expire adjust cage candy arch gather drum bullet absurd math era live bid rhythm alien crouch range attend journey unaware';

// Account 0 of the rescue-key scheme 0x0003 for these words.
export const TEST_WORDS_ACCOUNT_ZERO = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';
