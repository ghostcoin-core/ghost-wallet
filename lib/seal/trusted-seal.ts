// The Seal regions this app can vouch for. For each region: its id, its
// address, its ML-DSA-65 answer key, its code measurement (PCR0), its
// ML-KEM-768 key and the hash of the TLS certificate the relay is pinned to.
// Every Check, Fill and Open answer is checked against the Seal of the region
// that answered it, and against the app's pinned list
// (pinned-measurements.ts).
//
// They come only from each region's `GPA2` Nitro attestation, checked in the
// native core (seal-attestation.ts, docs/seal-app-attestation.md). Readers
// stay synchronous: `trustedSeal(region)` returns that region's Seal cached in
// memory, or null. Only a card flow (Check, Fill, Confirm and Open in
// flows.ts) awaits `refreshTrustedSeals`, which first hands the native relay
// the region list (`setSealRegions`), then fetches and checks, in parallel,
// the attestation of every region whose cached check has run out; opening the
// wallet, Home and Send never wait on it, and nothing is fetched at app start
// or in the background. Each region is cached on its own: a verified Seal 5
// minutes, a failure 30 seconds, memory only. One region failing never
// changes another. With no `SEAL_REGIONS` (today) there is no Seal, and every
// screen shows "Can't verify this card".
import type { GhostNfcSealPinNative, GhostNfcSealRegionsNative } from '../../modules/ghost-nfc';
import { setSealRegions } from '../../modules/ghost-nfc/relay';
import { appAttestationParts, loadTrustedSeal, type AttestationParts } from './seal-attestation';
import { SEAL_REGIONS, type SealRegion } from './seal-config';

/** A Seal region whose keys and measurement came from a checked attestation. */
export type TrustedSeal = {
  /** The region's id, as `SEAL_REGIONS` lists it. */
  region: string;
  /** The region's https:// address, where the relay sends its requests. */
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

/** The verified Seals by region id. */
export type TrustedSeals = ReadonlyMap<string, TrustedSeal>;

/** How long a verified Seal is kept, in milliseconds. */
export const VERIFIED_SEAL_MS = 300_000;
/** How long a failure is kept before the next card flow tries again, in milliseconds. */
export const FAILED_SEAL_MS = 30_000;

/** What `refreshTrustedSeals` runs on: each replaced by a fake in the tests. */
export type TrustedSealsDeps = Omit<AttestationParts, 'native'> & {
  /** The regions, in the Seal's release order (`SEAL_REGIONS`). */
  regions: readonly SealRegion[];
  /** The native fetch, pin and region list; undefined uses the app's module (null when the build has none). */
  native?: (GhostNfcSealPinNative & GhostNfcSealRegionsNative) | null;
};

/** The app's regions, core, clock and pinned list. */
export function trustedSealsDeps(): TrustedSealsDeps {
  return { ...appAttestationParts(), regions: SEAL_REGIONS };
}

type Entry = { url: string; seal: TrustedSeal | null; until: number };

const cached = new Map<string, Entry>();
const loading = new Map<string, { url: string; run: Promise<TrustedSeal | null> }>();

/** The Seal of `region` to check its cards with, or null when there is none this app can vouch for now. */
export function trustedSeal(region: string, now: number = Date.now()): TrustedSeal | null {
  const entry = cached.get(region);
  return entry && now < entry.until ? entry.seal : null;
}

/** One region's Seal, fetched and checked again when its cached result has run out. Never rejects. */
function refreshRegion(region: SealRegion, deps: TrustedSealsDeps): Promise<TrustedSeal | null> {
  const clock = deps.now;
  const entry = cached.get(region.id);
  if (entry && entry.url === region.url && clock() < entry.until) {
    return Promise.resolve(entry.seal);
  }
  const pending = loading.get(region.id);
  if (pending && pending.url === region.url) {
    return pending.run;
  }
  const run = (async () => {
    let seal: TrustedSeal | null = null;
    try {
      seal = await loadTrustedSeal({ ...deps, region: region.id, url: region.url });
    } catch {
      seal = null;
    }
    // Only the Seal of this very region and address is kept for it.
    if (seal && (seal.region !== region.id || seal.url !== region.url)) {
      seal = null;
    }
    cached.set(region.id, { url: region.url, seal, until: clock() + (seal ? VERIFIED_SEAL_MS : FAILED_SEAL_MS) });
    return seal;
  })();
  loading.set(region.id, { url: region.url, run });
  void run.finally(() => {
    if (loading.get(region.id)?.run === run) {
      loading.delete(region.id);
    }
  });
  return run;
}

/**
 * Hands the native relay the region list, then fetches and checks, in
 * parallel, every region whose cached check has run out. Returns the
 * verified Seals by region id (only listed regions); empty when there is
 * none, or when the list could not be handed to the relay (it could reach no
 * region). Never throws.
 */
export async function refreshTrustedSeals(deps: TrustedSealsDeps = trustedSealsDeps()): Promise<TrustedSeals> {
  const verified = new Map<string, TrustedSeal>();
  try {
    const regions = deps.regions;
    const listed = deps.native === undefined ? setSealRegions(regions) : setSealRegions(regions, deps.native);
    if (!listed || regions.length === 0) {
      return verified;
    }
    const seals = await Promise.all(regions.map((region) => refreshRegion(region, deps)));
    regions.forEach((region, i) => {
      const seal = seals[i];
      if (seal) {
        verified.set(region.id, seal);
      }
    });
  } catch {
    verified.clear();
  }
  return verified;
}

/** Forgets every cached Seal, so the next card flow checks each attestation again. */
export function forgetTrustedSeals(): void {
  cached.clear();
  loading.clear();
}
