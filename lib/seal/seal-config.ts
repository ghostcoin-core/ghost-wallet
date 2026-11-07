// The live Seal regions the app checks cards with
// (docs/seal-app-attestation.md).
//
// Each card is served by one region only, its home, chosen from the card's
// UID over this list by the native relay exactly as the Seal chooses it
// (docs/sealed-card.md, "Home region"). The list must therefore be ordered
// exactly like the Seal's release list (`RELEASE_REGIONS` in
// seal/src/journal_anchor.rs, and enclave/deploy/regions.json), with the same
// ids.
//
// These are the regions of the live Seal, release seal-2026-11-07c: each
// address is that region's stack Elastic IP, on port 443. An address alone
// trusts nothing: the app trusts a region only once its Nitro attestation
// checks against a build in pinned-measurements.ts, and then pins the TLS
// certificate the attestation names. Until a region's attestation checks,
// its cards show "Can't verify this card".

/** One live Seal region: its id, as the Seal's release lists it, and its address. */
export type SealRegion = { id: string; url: string };

/** The live Seal regions in the Seal's release order. */
export const SEAL_REGIONS: readonly SealRegion[] = [
  { id: 'us-east-1', url: 'https://23.20.15.18' },
  { id: 'eu-central-1', url: 'https://63.185.166.165' },
  { id: 'ap-southeast-1', url: 'https://18.140.26.20' },
];
