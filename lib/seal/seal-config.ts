// The Seal the app checks cards with (docs/seal-app-attestation.md).
//
// Empty until the live Seal exists: with no address the app fetches no
// attestation, trusts no Seal and shows "Can't verify this card" on every
// card screen. Putting the live https:// address here (with its first build
// in pinned-measurements.ts) is a later step.

/** The Seal's https:// address, or `""` while there is none. */
export const SEAL_URL = '';
