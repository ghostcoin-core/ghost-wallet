// The Seal this app can vouch for: its address, its ML-DSA-65 answer key and
// its code measurement (PCR0). Every Check, Fill and Open answer is checked
// against these and against the app's pinned list (pinned-measurements.ts).
//
// The key and measurement come from the Seal's Nitro attestation (the
// `GPA1` phone attestation, docs/seal-enclave.md). Fetching and checking that
// is a later step, so outside tests there is no Seal yet: `trustedSeal`
// returns nothing, and every screen shows "Can't verify this card" (and
// never an amount). Tests give it a fake Seal key.

/** A Seal whose key and measurement came from a checked attestation. */
export type TrustedSeal = {
  /** The Seal's https:// address, where the relay sends its requests. */
  url: string;
  /** The Seal's encoded ML-DSA-65 verifying key (1952 bytes). */
  verifyingKey: Uint8Array;
  /** The Seal's code measurement, PCR0 (48 bytes). */
  measurement: Uint8Array;
};

/** The Seal to check cards with, or null when there is none this app can vouch for. */
export function trustedSeal(): TrustedSeal | null {
  return null;
}
