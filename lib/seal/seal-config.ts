// The live Seal regions the app checks cards with
// (docs/seal-app-attestation.md).
//
// Each card is served by one region only, its home, chosen from the card's
// UID over this list by the native relay exactly as the Seal chooses it
// (docs/sealed-card.md, "Home region"). The list must therefore be ordered
// exactly like the Seal's release list (`RELEASE_REGIONS`), with the same ids.
//
// Empty until the live Seal exists: with no region the app fetches no
// attestation, trusts no Seal, opens no card sheet and shows "Can't verify
// this card" on every card screen. Filling in the live ids and addresses
// (with their first builds in pinned-measurements.ts) is a later step, done by
// the deploy.

/** One live Seal region: its id, as the Seal's release lists it, and its address. */
export type SealRegion = { id: string; url: string };

/** The live Seal regions in the Seal's release order; empty while there are none. */
export const SEAL_REGIONS: readonly SealRegion[] = [];
