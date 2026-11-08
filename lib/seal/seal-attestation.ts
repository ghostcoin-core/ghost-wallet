// The loader of one Seal region the app trusts (docs/seal-app-attestation.md).
//
// Only inside a card flow (Check, Fill, Open), never at app start or in the
// background, once for each listed region (trusted-seal.ts): for that
// region's address it makes a fresh 32-byte challenge (public), has the native
// module fetch the Seal's `GPA2` attestation over HTTPS with the hash of the
// certificate that connection presented, and has the native core check it
// (core/src/seal_attestation.rs: AWS's Nitro chain and signature, the PCRs
// against the pinned list, and the binding of the Seal's keys, this
// challenge and that certificate). Only a verified result gives a Seal, and
// only then is the relay pinned to that certificate (that region's host).
// A fetch that fails (an error, or past its 10 second deadline) is tried once
// more right away with a fresh challenge. Anything else (no address, no
// native module, a second fetch failure, any refusal) gives null and drops
// that region's pin, so cards homed there show "Can't verify this card",
// never an amount; the other regions are not touched. The checks are the
// same for every region.
// Nothing here is cryptography, and nothing here logs.
import {
  sealAttestationCore,
  type CorePinnedSealBuild,
  type CoreSealAttestationVerdict,
  type SealAttestationBindings,
} from '../../modules/ghost-core';
import type { GhostNfcSealPinNative } from '../../modules/ghost-nfc';
import { fetchSealAttestation, SealRelayError, setSealPin } from '../../modules/ghost-nfc/relay';
import { PINNED_MEASUREMENTS, type MeasurementList } from './pinned-measurements';
import type { SealRegion } from './seal-config';
import type { TrustedSeal } from './trusted-seal';

/** How long one region's attestation fetch may take, in milliseconds. */
export const ATTESTATION_DEADLINE_MS = 10_000;

/** What the loader runs on, for every region alike: each replaced by a fake in the tests. */
export type AttestationParts = {
  /** The native fetch and pin; undefined uses the app's module (null when the build has none). */
  native?: GhostNfcSealPinNative | null;
  /** The native core's check; null when the build has none. */
  core: () => SealAttestationBindings | null;
  /** Milliseconds since the Unix epoch. */
  now: () => number;
  /** A fresh 32-byte challenge (public); undefined takes it from the core's random source. */
  random?: () => Uint8Array;
  list: MeasurementList;
  /** The fetch's deadline in milliseconds; undefined is `ATTESTATION_DEADLINE_MS`. */
  deadlineMs?: number;
};

/** What the loader of one region runs on. */
export type SealAttestationDeps = AttestationParts & {
  /** The region's id, as `SEAL_REGIONS` lists it; `""` means no Seal. */
  region: string;
  /** The region's https:// address; `""` means no Seal. */
  url: string;
};

function optionalCore(): SealAttestationBindings | null {
  try {
    return sealAttestationCore();
  } catch {
    return null;
  }
}

/** The app's core, clock and pinned list. */
export function appAttestationParts(): AttestationParts {
  return { core: optionalCore, now: () => Date.now(), list: PINNED_MEASUREMENTS };
}

/** The app's loader of `region`. */
export function attestationDeps(region: SealRegion, parts: AttestationParts = appAttestationParts()): SealAttestationDeps {
  return { ...parts, region: region.id, url: region.url };
}

/** `run`, or a `seal-unreachable` failure once `ms` have passed without it settling. */
function withDeadline<T>(run: Promise<T>, ms: number): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  const late = new Promise<never>((_, reject) => {
    timer = setTimeout(() => reject(new SealRelayError('seal-unreachable')), ms);
  });
  return Promise.race([run, late]).finally(() => clearTimeout(timer));
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

/**
 * One region's attestation, checked: its Seal, or no Seal and the first
 * check that failed, as a short code (never a key, hash or challenge).
 */
export type AttestedSeal = { seal: TrustedSeal; reason: '' } | { seal: null; reason: string };

function failed(reason: string): AttestedSeal {
  return { seal: null, reason };
}

/** The region's Seal from the core's verdict, or why there is none: the core's refusal, or anything malformed. */
function sealOf(
  region: string,
  url: string,
  verdict: CoreSealAttestationVerdict | null | undefined,
  tlsCertSha256: Uint8Array,
): AttestedSeal {
  if (!verdict) {
    return failed('no-verdict');
  }
  if (verdict.refusal !== '') {
    return failed(verdict.refusal);
  }
  const seal = verdict.seal;
  if (!seal) {
    return failed('no-seal-in-verdict');
  }
  const verifyingKey = view(seal.verifyingKey, 1952);
  const kemKey = view(seal.kemKey, 1184);
  const measurement = view(seal.measurement, 48);
  if (!verifyingKey || !kemKey || !measurement) {
    return failed('malformed-seal');
  }
  return { seal: { region, url, verifyingKey, measurement, kemKey, tlsCertSha256 }, reason: '' };
}

/** How many times one region's attestation is fetched before it is dropped: once, and once more right away. */
export const ATTESTATION_FETCH_TRIES = 2;

/** The code of a fetch that failed: the native cause (`attest-network(-1200)`) or the relay problem. */
function fetchFailure(error: unknown): string {
  return error instanceof SealRelayError ? error.reason : 'fetch-failed';
}

/**
 * Fetches and checks one region's attestation, and keeps the first failure:
 * the fetch's error code, the core's refusal, or `pin-failed`. A fetch that
 * fails is tried once more right away, with a fresh challenge, and the
 * second failure is the one kept; the checks of the answer are the same.
 * Never throws: any failure is no Seal, with that region's pin dropped.
 */
export async function attestSeal(deps: SealAttestationDeps): Promise<AttestedSeal> {
  const url = deps.url;
  if (!url || !deps.region) {
    return failed('no-address');
  }
  const pin = (hash: Uint8Array | null) => (deps.native === undefined ? setSealPin(url, hash) : setSealPin(url, hash, deps.native));
  const drop = (reason: string): AttestedSeal => {
    try {
      pin(null);
    } catch {
      // Dropping a pin never fails the loader.
    }
    return failed(reason);
  };
  let step = 'no-core';
  try {
    const core = deps.core();
    if (!core) {
      return drop('no-core');
    }
    let challenge: Uint8Array = new Uint8Array(0);
    let fetched: Awaited<ReturnType<typeof fetchSealAttestation>> | null = null;
    let fetchFailed = 'fetch-failed';
    for (let tries = 0; tries < ATTESTATION_FETCH_TRIES && !fetched; tries += 1) {
      step = 'no-challenge';
      // A fresh challenge for every fetch, the retry's included.
      challenge = deps.random ? deps.random() : new Uint8Array(core.sealAttestationChallenge());
      if (challenge.length !== 32) {
        return drop('no-challenge');
      }
      try {
        fetched = await withDeadline(
          deps.native === undefined ? fetchSealAttestation(url, challenge) : fetchSealAttestation(url, challenge, deps.native),
          deps.deadlineMs ?? ATTESTATION_DEADLINE_MS,
        );
      } catch (error) {
        fetchFailed = fetchFailure(error);
      }
    }
    if (!fetched) {
      return drop(fetchFailed);
    }
    step = 'core-failed';
    const verdict = core.verifySealAttestation({
      attestation: buffer(fetched.attestation),
      challenge: buffer(challenge),
      tlsCertSha256: buffer(fetched.certSha256),
      pinnedBuilds: pinnedBuilds(deps.list),
      now: BigInt(Math.floor(deps.now() / 1000)),
    });
    const attested = sealOf(deps.region, url, verdict, fetched.certSha256);
    if (!attested.seal) {
      return drop(attested.reason);
    }
    step = 'pin-failed';
    if (!pin(attested.seal.tlsCertSha256)) {
      return drop('pin-failed');
    }
    return attested;
  } catch {
    return drop(step);
  }
}

/**
 * Fetches and checks one region's attestation (`attestSeal`). Never throws: any
 * failure is null, with that region's pin dropped (`attestSeal` says why).
 */
export async function loadTrustedSeal(deps: SealAttestationDeps): Promise<TrustedSeal | null> {
  return (await attestSeal(deps)).seal;
}
