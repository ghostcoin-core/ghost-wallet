// The Seal this app can vouch for: its address, its ML-DSA-65 answer key,
// its code measurement (PCR0), its ML-KEM-768 key and the hash of the TLS
// certificate the relay is pinned to. Every Check, Fill and Open answer is
// checked against these and against the app's pinned list
// (pinned-measurements.ts).
//
// They come only from the Seal's `GPA2` Nitro attestation, checked in the
// native core (seal-attestation.ts, docs/seal-app-attestation.md). Readers
// stay synchronous: `trustedSeal` returns the Seal cached in memory, or
// null. Only a card flow (Check, Fill, Open in flows.ts) awaits
// `refreshTrustedSeal`, which fetches and checks the attestation when the
// cache has run out; opening the wallet, Home and Send never wait on it. A
// verified Seal is kept 5 minutes, a failure 30 seconds. With no `SEAL_URL`
// (today) there is no Seal, and every screen shows "Can't verify this card".
import { loadTrustedSeal, type SealAttestationDeps } from './seal-attestation';

/** A Seal whose keys and measurement came from a checked attestation. */
export type TrustedSeal = {
  /** The Seal's https:// address, where the relay sends its requests. */
  url: string;
  /** The Seal's encoded ML-DSA-65 verifying key (1952 bytes). */
  verifyingKey: Uint8Array;
  /** The Seal's code measurement, PCR0 (48 bytes). */
  measurement: Uint8Array;
  /** The Seal's ML-KEM-768 encapsulation key (1184 bytes). */
  kemKey: Uint8Array;
  /** SHA-256 of the DER of the Seal's TLS certificate, the relay's pin (32 bytes). */
  tlsCertSha256: Uint8Array;
};

/** How long a verified Seal is kept, in milliseconds. */
export const VERIFIED_SEAL_MS = 300_000;
/** How long a failure is kept before the next card flow tries again, in milliseconds. */
export const FAILED_SEAL_MS = 30_000;

let cached: { seal: TrustedSeal | null; until: number } | null = null;
let loading: Promise<TrustedSeal | null> | null = null;

/** The Seal to check cards with, or null when there is none this app can vouch for now. */
export function trustedSeal(now: number = Date.now()): TrustedSeal | null {
  return cached && now < cached.until ? cached.seal : null;
}

/**
 * The Seal, fetched and checked again when the cached result has run out.
 * Never throws; null when there is no Seal to vouch for.
 */
export function refreshTrustedSeal(deps?: SealAttestationDeps): Promise<TrustedSeal | null> {
  const clock = deps?.now ?? Date.now;
  if (cached && clock() < cached.until) {
    return Promise.resolve(cached.seal);
  }
  if (loading) {
    return loading;
  }
  const run = (async () => {
    let seal: TrustedSeal | null = null;
    try {
      seal = await loadTrustedSeal(deps);
    } catch {
      seal = null;
    }
    cached = { seal, until: clock() + (seal ? VERIFIED_SEAL_MS : FAILED_SEAL_MS) };
    return seal;
  })();
  loading = run;
  void run.finally(() => {
    if (loading === run) {
      loading = null;
    }
  });
  return run;
}

/** Forgets the cached Seal, so the next card flow checks the attestation again. */
export function forgetTrustedSeal(): void {
  cached = null;
  loading = null;
}
