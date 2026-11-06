// The loader of the Seal the app trusts (docs/seal-app-attestation.md).
//
// Only inside a card flow (Check, Fill, Open), never at app start or in the
// background: it makes a fresh 32-byte challenge (public), has the native
// module fetch the Seal's `GPA2` attestation over HTTPS with the hash of the
// certificate that connection presented, and has the native core check it
// (core/src/seal_attestation.rs: AWS's Nitro chain and signature, the PCRs
// against the pinned list, and the binding of the Seal's keys, this
// challenge and that certificate). Only a verified result gives a Seal, and
// only then is the relay pinned to that certificate. Anything else (no
// address, no native module, a fetch error, any refusal) gives null and
// drops the pin, so the screens show "Can't verify this card", never an
// amount. Nothing here is cryptography, and nothing here logs.
import {
  sealAttestationCore,
  type CorePinnedSealBuild,
  type CoreSealAttestationVerdict,
  type SealAttestationBindings,
} from '../../modules/ghost-core';
import type { GhostNfcSealPinNative } from '../../modules/ghost-nfc';
import { fetchSealAttestation, setSealPin } from '../../modules/ghost-nfc/relay';
import { PINNED_MEASUREMENTS, type MeasurementList } from './pinned-measurements';
import { SEAL_URL } from './seal-config';
import type { TrustedSeal } from './trusted-seal';

/** What the loader runs on: each replaced by a fake in the tests. */
export type SealAttestationDeps = {
  /** The Seal's address (`SEAL_URL`); `""` means no Seal. */
  url: string;
  /** The native fetch and pin; undefined uses the app's module (null when the build has none). */
  native?: GhostNfcSealPinNative | null;
  /** The native core's check; null when the build has none. */
  core: () => SealAttestationBindings | null;
  /** Milliseconds since the Unix epoch. */
  now: () => number;
  /** A fresh 32-byte challenge (public); undefined takes it from the core's random source. */
  random?: () => Uint8Array;
  list: MeasurementList;
};

function optionalCore(): SealAttestationBindings | null {
  try {
    return sealAttestationCore();
  } catch {
    return null;
  }
}

/** The app's address, core, clock and pinned list. */
export function attestationDeps(): SealAttestationDeps {
  return { url: SEAL_URL, core: optionalCore, now: () => Date.now(), list: PINNED_MEASUREMENTS };
}

function bytes(hex: string): Uint8Array {
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(2 * i, 2 * i + 2), 16));
}

function buffer(view: Uint8Array): ArrayBuffer {
  return view.buffer.slice(view.byteOffset, view.byteOffset + view.byteLength) as ArrayBuffer;
}

function view(data: ArrayBuffer | Uint8Array | undefined, length: number): Uint8Array | null {
  if (!data) {
    return null;
  }
  const out = data instanceof Uint8Array ? data.slice() : new Uint8Array(data.slice(0));
  return out.length === length ? out : null;
}

/** Every build of the pinned list, revoked ones included and flagged, as the core takes them. */
export function pinnedBuilds(list: MeasurementList = PINNED_MEASUREMENTS): CorePinnedSealBuild[] {
  return list.builds.map((build) => ({
    name: build.name,
    pcr0: buffer(bytes(build.pcr0)),
    pcr1: buffer(bytes(build.pcr1)),
    pcr2: buffer(bytes(build.pcr2)),
    allowed: build.status === 'allowed',
  }));
}

/** The Seal from the core's verdict, or null for any refusal or anything malformed. */
function sealOf(url: string, verdict: CoreSealAttestationVerdict | null | undefined, tlsCertSha256: Uint8Array): TrustedSeal | null {
  const seal = verdict?.seal;
  if (!verdict || verdict.refusal !== '' || !seal) {
    return null;
  }
  const verifyingKey = view(seal.verifyingKey, 1952);
  const kemKey = view(seal.kemKey, 1184);
  const measurement = view(seal.measurement, 48);
  if (!verifyingKey || !kemKey || !measurement) {
    return null;
  }
  return { url, verifyingKey, measurement, kemKey, tlsCertSha256 };
}

/**
 * Fetches and checks the Seal's attestation once. Never throws: any failure
 * is null, with the relay's pin dropped.
 */
export async function loadTrustedSeal(deps: SealAttestationDeps = attestationDeps()): Promise<TrustedSeal | null> {
  const url = deps.url;
  if (!url) {
    return null;
  }
  const pin = (hash: Uint8Array | null) => (deps.native === undefined ? setSealPin(url, hash) : setSealPin(url, hash, deps.native));
  try {
    const core = deps.core();
    if (!core) {
      pin(null);
      return null;
    }
    const challenge = deps.random ? deps.random() : new Uint8Array(core.sealAttestationChallenge());
    if (challenge.length !== 32) {
      pin(null);
      return null;
    }
    const fetched =
      deps.native === undefined ? await fetchSealAttestation(url, challenge) : await fetchSealAttestation(url, challenge, deps.native);
    const verdict = core.verifySealAttestation({
      attestation: buffer(fetched.attestation),
      challenge: buffer(challenge),
      tlsCertSha256: buffer(fetched.certSha256),
      pinnedBuilds: pinnedBuilds(deps.list),
      now: BigInt(Math.floor(deps.now() / 1000)),
    });
    const seal = sealOf(url, verdict, fetched.certSha256);
    if (!seal || !pin(seal.tlsCertSha256)) {
      pin(null);
      return null;
    }
    return seal;
  } catch {
    try {
      pin(null);
    } catch {
      // Dropping a pin never fails the loader.
    }
    return null;
  }
}
