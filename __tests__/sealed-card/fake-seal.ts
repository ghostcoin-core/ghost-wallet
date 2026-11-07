// A fake Seal, a fake card, a fake native relay and a fake native core for
// the Sealed card tests (test only).
//
// The fake Seal runs Check, Fill, the Fill's confirmation and Open on the
// fake card the way seal/src/flows.rs does, and answers in the real 203-byte
// layout. It "signs" with a keyed checksum under its fake key instead of
// ML-DSA-65 (the real signature checks are core/tests/seal_answer.rs). The
// fake core checks answers in the order core/src/seal_answer.rs does. The
// fake relay behaves like ios/SealRelay.swift: it makes the challenge, carries
// the flow, refuses an answer of another flow, challenge or card, and hands an
// Open's release to the core, never to JavaScript. Called with no Seal
// address, it sends the flow to the card's home region of the list it was
// handed (`setSealRegions`), and names that region in its result; the home
// regions come from a table of the fixed vectors the Rust core is tested
// against (core/tests/seal_home_region.rs), not from a hash in JavaScript.
import type { SealBindings, CoreSealAnswerCheck, CoreSealAnswerVerdict } from '../../modules/ghost-core';
import type { GhostNfcSealRegionsNative } from '../../modules/ghost-nfc';
import type { GhostNfcSealNative, NativeSealCheck, SealRegionAddress } from '../../modules/ghost-nfc/relay';
import type { TrustedSeal } from '../../lib/seal/trusted-seal';

export const FAKE_MEASUREMENT_HEX = '5e'.repeat(48);
export const OTHER_MEASUREMENT_HEX = '6f'.repeat(48);
export const FAKE_SEAL_URL = 'https://seal.example:8443';
/** The one region of a single-region world. */
export const FAKE_REGION = 'eu-central-1';
export const UID_HEX = '04518DFAA96180';
export const GHOST = 10n ** 18n;

/** Three regions, in the Seal's release order. */
export const THREE_REGIONS = ['us-east-1', 'eu-central-1', 'ap-southeast-1'] as const;

/** The home region of each fixed vector card over `THREE_REGIONS` (core/tests/seal_home_region.rs). */
export const HOME_VECTORS: readonly { uid: string; home: string }[] = [
  { uid: '04518DFAA96180', home: 'eu-central-1' },
  { uid: '0412345678ABCD', home: 'ap-southeast-1' },
  { uid: '04FFFFFFFFFFFF', home: 'eu-central-1' },
  { uid: '04000000000001', home: 'ap-southeast-1' },
  { uid: '04A1B2C3D4E5F6', home: 'us-east-1' },
];

/** A fake region's address (test only). */
export function regionUrl(id: string): string {
  return `https://${id}.seal.example`;
}

/** The pinned list the tests give the app: one allowed build, the fake Seal's. */
export const PINNED_JSON = JSON.stringify({
  version: 1,
  builds: [
    { name: 'fake-seal-test', released: '2026-11-01', pcr0: FAKE_MEASUREMENT_HEX, pcr1: '11'.repeat(48), pcr2: '22'.repeat(48), status: 'allowed' },
  ],
});

export function bytesOf(hex: string): Uint8Array {
  return Uint8Array.from({ length: hex.length / 2 }, (_, i) => parseInt(hex.slice(2 * i, 2 * i + 2), 16));
}

export function hexOf(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

function view(data: ArrayBuffer | Uint8Array): Uint8Array {
  return data instanceof Uint8Array ? data : new Uint8Array(data);
}

function same(a: ArrayBuffer | Uint8Array, b: ArrayBuffer | Uint8Array): boolean {
  const x = view(a);
  const y = view(b);
  return x.length === y.length && x.every((byte, i) => byte === y[i]);
}

function buffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.slice().buffer as ArrayBuffer;
}

/** A 32-byte stand-in hash (test only, not a real hash). */
export function fakeHash(data: Uint8Array, salt = 0): Uint8Array<ArrayBuffer> {
  const out = new Uint8Array(32);
  let h = (0x811c9dc5 ^ salt) >>> 0;
  for (let round = 0; round < 32; round += 1) {
    for (const byte of data) {
      h = Math.imul(h ^ byte, 0x01000193) >>> 0;
    }
    h = Math.imul(h ^ (round + 1), 0x01000193) >>> 0;
    out[round] = h & 0xff;
  }
  return out;
}

/** The fake Seal's stand-in signature: a keyed checksum (test only). */
export function fakeSign(key: Uint8Array, bytes: Uint8Array): Uint8Array {
  return fakeHash(Uint8Array.from([...key, ...bytes]), 7);
}

const STATES = ['empty', 'sealed', 'opening', 'opened'] as const;
const KINDS = ['check', 'fill', 'open'] as const;

type Body = {
  kind: 1 | 2 | 3;
  challenge: Uint8Array;
  uid: Uint8Array;
  generation: number;
  coin: Uint8Array;
  measurement: Uint8Array;
  state: 0 | 1 | 2 | 3;
  amountWei: bigint;
  expiresAt: number;
  binding: Uint8Array;
  pinRequired: boolean;
  pinTriesLeft: number;
};

export function encodeAnswer(body: Body): Uint8Array {
  const out = new Uint8Array(203);
  out.set(Array.from('ghost-seal/v1/answer', (c) => c.charCodeAt(0)), 0);
  out[20] = body.kind;
  out.set(body.challenge, 21);
  out.set(body.uid, 53);
  new DataView(out.buffer).setUint32(60, body.generation);
  out.set(body.coin, 64);
  out.set(body.measurement, 96);
  out[144] = body.state;
  let amount = body.amountWei;
  for (let i = 160; i >= 145; i -= 1) {
    out[i] = Number(amount & 0xffn);
    amount >>= 8n;
  }
  new DataView(out.buffer).setBigUint64(161, BigInt(body.expiresAt));
  out.set(body.binding, 169);
  out[201] = body.pinRequired ? 1 : 0;
  out[202] = body.pinRequired ? body.pinTriesLeft : 0;
  return out;
}

/** A Ghost Sealed card, as the Seal sees it. */
export class FakeCard {
  uid = bytesOf(UID_HEX);
  /** A card the Seal never set up answers as no Ghost card. */
  ghost = true;
  state: 'empty' | 'sealed' | 'opening' | 'opened' = 'empty';
  /** A key is in the slot (a Fill was written). */
  keyPresent = false;
  generation = 0;
  amountWei = 0n;
  coin = new Uint8Array(32);
  pin: string | null = null;
  tries = 0;
}

export type Tamper = 'bad-signature' | 'other-key' | 'replay' | 'expired' | 'other-measurement' | 'other-card' | null;

/** The Seal, with the chain check it asks. */
export class FakeSeal {
  key = bytesOf('a1'.repeat(32));
  measurement = bytesOf(FAKE_MEASUREMENT_HEX);
  tamper: Tamper = null;
  /** The Seal cannot be reached at all. */
  offline = false;
  /** The chain check's nodes cannot be reached. */
  chainDown = false;
  /** The coin's payment is final and settled on the chain. */
  paid = false;
  spent = false;
  /** The commit data a Fill journaled, by card. */
  fills = new Map<string, { commitData: Uint8Array; amountWei: bigint; pin: string | null }>();
  /** The phone key an Open journaled, by card. */
  opens = new Map<string, string>();
  /** Every answer signed, newest last: what a replay sends again. */
  signed: { answer: Uint8Array; signature: Uint8Array }[] = [];
  /** How many Open PIN comparisons were made. */
  pinTries = 0;
  /** Whatever the Seal was sent last, for the tests' look at what crossed. */
  lastRequest: Record<string, string> = {};
  /** How many start requests reached this Seal. */
  starts = 0;
  /** This Seal is not the card's home: it refuses every start `wrong-region`, naming another region. */
  wrongRegion = false;

  sign(answer: Uint8Array): { answer: Uint8Array; signature: Uint8Array } {
    const key = this.tamper === 'other-key' ? bytesOf('b2'.repeat(32)) : this.key;
    const signature = fakeSign(key, answer);
    if (this.tamper === 'bad-signature') {
      signature[3] ^= 0x01;
    }
    this.signed.push({ answer, signature });
    return { answer, signature };
  }
}

class Refused extends Error {
  readonly code: string;

  constructor(code: string) {
    super(`refused: ${code}`);
    this.code = code;
  }
}

function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}

/** The native core's Sealed card calls, faked: the answer checks of core/src/seal_answer.rs, in order. */
export class FakeCore implements SealBindings {
  phoneKey: Uint8Array | null = null;
  release: Uint8Array | null = null;
  cardKeyHeld = false;
  private made = 0;
  checks: CoreSealAnswerCheck[] = [];

  verify(check: CoreSealAnswerCheck, bound: Uint8Array | null): CoreSealAnswerVerdict {
    this.checks.push(check);
    const refuse = (refusal: string): CoreSealAnswerVerdict => ({ refusal });
    if (!check.pinnedMeasurements.some((pinned) => same(pinned, check.measurement))) {
      return refuse('not-pinned');
    }
    const answer = view(check.answer);
    if (!same(fakeSign(view(check.verifyingKey), answer), check.signature)) {
      return refuse('bad-signature');
    }
    if (answer.length !== 203) {
      return refuse('malformed');
    }
    if (!same(answer.slice(96, 144), check.measurement)) {
      return refuse('wrong-measurement');
    }
    const kind = KINDS[answer[20] - 1];
    if (kind !== check.kind) {
      return refuse('wrong-kind');
    }
    if (!same(answer.slice(21, 53), check.challenge)) {
      return refuse('wrong-challenge');
    }
    if (!same(answer.slice(53, 60), check.uid)) {
      return refuse('wrong-card');
    }
    const data = new DataView(answer.buffer, answer.byteOffset);
    const expiresAt = data.getBigUint64(161);
    if (check.now >= expiresAt) {
      return refuse('expired');
    }
    if (bound && (!same(answer.slice(169, 201), fakeHash(bound)) || (kind === 'fill' && !same(answer.slice(64, 96), fakeHash(bound))))) {
      return refuse('wrong-binding');
    }
    let amount = 0n;
    for (const byte of answer.slice(145, 161)) {
      amount = (amount << 8n) | BigInt(byte);
    }
    return {
      refusal: '',
      answer: {
        kind,
        uid: buffer(answer.slice(53, 60)),
        generation: data.getUint32(60),
        coin: buffer(answer.slice(64, 96)),
        state: STATES[answer[144]],
        amountWei: amount.toString(),
        expiresAt,
        binding: buffer(answer.slice(169, 201)),
        pinRequired: answer[201] === 1,
        pinTriesLeft: answer[202],
      },
    };
  }

  verifySealAnswer(check: CoreSealAnswerCheck): CoreSealAnswerVerdict {
    return this.verify(check, null);
  }

  verifySealFillAnswer(check: CoreSealAnswerCheck, commitData: ArrayBuffer): CoreSealAnswerVerdict {
    return check.kind === 'fill' ? this.verify(check, view(commitData)) : { refusal: 'wrong-kind' };
  }

  sealOpenPhoneKey(): ArrayBuffer {
    if (!this.phoneKey) {
      this.made += 1;
      this.phoneKey = new Uint8Array(1184).fill(this.made);
    }
    return buffer(this.phoneKey);
  }

  hasSealOpenKey(): boolean {
    return this.phoneKey !== null;
  }

  forgetSealOpenKey(): void {
    this.phoneKey = null;
    this.release = null;
  }

  /** What ghost_wallet_seal_open_take_release does: the relay hands the release to the core. */
  takeRelease(release: Uint8Array): number {
    if (!this.phoneKey) {
      return -1;
    }
    this.release = release;
    return 0;
  }

  finishSealOpen(check: CoreSealAnswerCheck): CoreSealAnswerVerdict {
    if (check.kind !== 'open') {
      return { refusal: 'wrong-kind' };
    }
    if (!this.phoneKey) {
      return { refusal: 'no-phone-key' };
    }
    const release = this.release;
    this.release = null;
    if (!release) {
      return { refusal: 'no-release' };
    }
    const verdict = this.verify(check, release);
    if (verdict.refusal !== '' || verdict.answer?.state !== 'opened') {
      return verdict.refusal !== '' ? verdict : { refusal: 'wrong-kind' };
    }
    // The fake release opens only for the phone key it was made for.
    if (!same(release.slice(4, 36), fakeHash(this.phoneKey))) {
      return { refusal: 'bad-release' };
    }
    this.cardKeyHeld = true;
    return verdict;
  }

  // The card-key calls of core/src/card.rs the screens use.
  hasCardKey(): boolean {
    return this.cardKeyHeld;
  }

  forgetCardKey(): void {
    this.cardKeyHeld = false;
  }
}

/** The fake world one test runs in: the Seal, the card in the field, the core and the relay. */
export class World {
  seal = new FakeSeal();
  card = new FakeCard();
  core = new FakeCore();
  /** The seam has no Seal (as outside tests today). */
  noSeal = false;
  nfc = true;
  /** The person closes the card sheet. */
  cancel = false;
  /** The Open's phone key seed kept in the Keychain. */
  keychain: Uint8Array | null = null;
  /** Challenges the relay sent, in order. */
  challenges: Uint8Array[] = [];
  native: GhostNfcSealNative & GhostNfcSealRegionsNative;
  calls: string[] = [];
  /** Run before a flow resolves, to hold it (the spinner tests). */
  gate: Promise<void> | null = null;
  /** The next flow finishes on the Seal, but its answer never reaches the phone. */
  dropAfterFlow = false;

  constructor() {
    this.native = this.makeNative();
  }

  /** How many times a card flow asked for the Seals' attestations to be checked again. */
  refreshes = 0;

  /** The listed regions, in the Seal's release order (what `SEAL_REGIONS` would hold). */
  regions: SealRegionAddress[] = [{ id: FAKE_REGION, url: FAKE_SEAL_URL }];
  /** Each region's Seal; the one region of a single-region world is `seal`. */
  regionSeals = new Map<string, FakeSeal>([[FAKE_REGION, this.seal]]);
  /** Regions whose attestation fails now. */
  unverified = new Set<string>();
  /** The region list the native relay holds (`setSealRegions`); null until it is handed one. */
  nativeRegions: SealRegionAddress[] | null = null;
  /** The region each relay call ran in, in order (`""` for a typed address). */
  regionsUsed: string[] = [];
  /** The Seal serving the flow being relayed. */
  private serving: FakeSeal = this.seal;

  /** Lists `ids` as the regions, each with a Seal of its own key, all with the same pinned build. */
  useRegions(ids: readonly string[]): void {
    this.regions = ids.map((id) => ({ id, url: regionUrl(id) }));
    this.regionSeals = new Map<string, FakeSeal>(
      ids.map((id, i): [string, FakeSeal] => {
        const seal = new FakeSeal();
        seal.key = bytesOf((0xa1 + i).toString(16).padStart(2, '0').repeat(32));
        return [id, seal];
      }),
    );
    this.seal = this.regionSeals.get(ids[0])!;
  }

  /** The Seal of `region` (test only). */
  sealOf(region: string): FakeSeal {
    const seal = this.regionSeals.get(region);
    if (!seal) {
      throw new Error(`no fake Seal for ${region}`);
    }
    return seal;
  }

  /** The verified Seal of `region` (the first listed by default), or null when its attestation fails now. */
  trustedSeal(region: string = this.regions[0]?.id ?? ''): TrustedSeal | null {
    const listed = this.regions.find((r) => r.id === region);
    const seal = this.regionSeals.get(region);
    if (this.noSeal || !listed || !seal || this.unverified.has(region)) {
      return null;
    }
    return {
      region,
      url: listed.url,
      verifyingKey: seal.key,
      measurement: seal.measurement,
      kemKey: new Uint8Array(1184).fill(0x4b),
      tlsCertSha256: new Uint8Array(32).fill(0x7e),
    };
  }

  /** Every verified Seal now, by region id. */
  trusted(): Map<string, TrustedSeal> {
    const seals = new Map<string, TrustedSeal>();
    for (const region of this.regions) {
      const seal = this.trustedSeal(region.id);
      if (seal) {
        seals.set(region.id, seal);
      }
    }
    return seals;
  }

  /**
   * What `refreshTrustedSeals` gives a card flow: it hands the native relay
   * the list first, then gives the Seals as their attestations say now.
   */
  refreshed(): Map<string, TrustedSeal> {
    this.refreshes += 1;
    this.nativeRegions = this.regions.map((r) => ({ ...r }));
    return this.trusted();
  }

  /** Puts a fresh card, set up and empty, in the field. */
  newCard(uid: string = UID_HEX): FakeCard {
    this.card = new FakeCard();
    this.card.uid = bytesOf(uid);
    return this.card;
  }

  /** Makes the card Sealed with `amountWei`, as a confirmed Fill leaves it. */
  sealedCard(amountWei: bigint, pin: string | null = null, uid: string = UID_HEX): FakeCard {
    const card = this.newCard(uid);
    card.state = 'sealed';
    card.keyPresent = true;
    card.amountWei = amountWei;
    card.coin = fakeHash(Uint8Array.from([1, 2, 3]));
    card.pin = pin;
    card.tries = pin ? 5 : 0;
    for (const seal of this.regionSeals.values()) {
      seal.paid = true;
    }
    return card;
  }

  /** The card's home region of `list`: the only one, or the fixed vectors' answer over three. */
  private homeOf(list: readonly SealRegionAddress[]): string {
    if (list.length === 1) {
      return list[0].id;
    }
    const uid = hexOf(this.card.uid).toUpperCase();
    const vector = HOME_VECTORS.find((v) => v.uid === uid);
    if (!vector || list.map((r) => r.id).join() !== THREE_REGIONS.join()) {
      throw new Error('test: no home vector for this card and list');
    }
    return vector.home;
  }

  private answer(kind: 1 | 2 | 3, challenge: Uint8Array, fields: Partial<Body>): { answer: Uint8Array; signature: Uint8Array } {
    const seal = this.serving;
    if (seal.tamper === 'replay' && seal.signed.length > 0) {
      // An old answer, signed over an earlier challenge.
      return seal.signed[0];
    }
    const card = this.card;
    const body: Body = {
      kind,
      challenge,
      uid: seal.tamper === 'other-card' ? bytesOf('04000000000001') : card.uid,
      generation: card.generation,
      coin: new Uint8Array(32),
      measurement: seal.tamper === 'other-measurement' ? bytesOf(OTHER_MEASUREMENT_HEX) : seal.measurement,
      state: 0,
      amountWei: 0n,
      expiresAt: seal.tamper === 'expired' ? nowSeconds() - 1 : nowSeconds() + 120,
      binding: new Uint8Array(32),
      pinRequired: false,
      pinTriesLeft: 0,
      ...fields,
    };
    return seal.sign(encodeAnswer(body));
  }

  private pinStatus(): Partial<Body> {
    return this.card.pin ? { pinRequired: true, pinTriesLeft: this.card.tries } : {};
  }

  /** seal/src/flows.rs `check`, with the chain status check installed. */
  private check(challenge: Uint8Array) {
    const card = this.card;
    const journaled = this.serving.opens.get(hexOf(card.uid));
    if (journaled || card.state === 'opening' || card.state === 'opened') {
      const state = card.state === 'opened' ? 3 : 2;
      return this.answer(1, challenge, { state, coin: card.coin, amountWei: card.amountWei });
    }
    if (card.state === 'empty') {
      // A Fill waiting for its payment is answered Empty, with no coin.
      return this.answer(1, challenge, { state: 0, ...this.pinStatus() });
    }
    if (card.pin && card.tries === 0) {
      throw new Refused('ERR_SEAL_PIN_LOCKED');
    }
    this.chainStatus();
    return this.answer(1, challenge, { state: 1, coin: card.coin, amountWei: card.amountWei, ...this.pinStatus() });
  }

  private chainStatus() {
    if (this.serving.chainDown) {
      throw new Refused('ERR_SEAL_CANT_CHECK');
    }
    if (this.serving.spent) {
      throw new Refused('ERR_SEAL_SPENT');
    }
    if (!this.serving.paid) {
      throw new Refused('ERR_SEAL_FILLING');
    }
  }

  /** seal/src/flows.rs `fill`. */
  private fill(challenge: Uint8Array, amountWei: bigint, pin: string | null) {
    const card = this.card;
    const uid = hexOf(card.uid);
    if (card.state !== 'empty') {
      throw new Refused('ERR_SEAL_WRONG_STATE');
    }
    let pending = this.serving.fills.get(uid);
    if (card.keyPresent) {
      if (!pending || pending.amountWei !== amountWei || pending.pin !== pin) {
        throw new Refused('ERR_SEAL_FILL_PENDING');
      }
    } else {
      const n = this.serving.fills.size + 1;
      pending = { commitData: new Uint8Array(430).map((_, i) => (i * 7 + n) & 0xff), amountWei, pin };
      this.serving.fills.set(uid, pending);
      card.keyPresent = true;
      card.amountWei = amountWei;
      card.coin = fakeHash(pending.commitData);
      card.pin = pin;
      card.tries = pin ? 5 : 0;
    }
    const coin = fakeHash(pending.commitData);
    return {
      ...this.answer(2, challenge, { state: 0, coin, amountWei, binding: coin, ...this.pinStatus() }),
      commitData: pending.commitData,
    };
  }

  /** seal/src/flows.rs `confirm_fill`. */
  private confirm(challenge: Uint8Array) {
    const card = this.card;
    if (card.state === 'empty' && card.keyPresent) {
      this.chainStatus();
      card.state = 'sealed';
    } else if (card.state !== 'sealed') {
      throw new Refused('ERR_SEAL_WRONG_STATE');
    } else {
      this.chainStatus();
    }
    return this.answer(2, challenge, { state: 1, coin: card.coin, amountWei: card.amountWei, binding: card.coin, ...this.pinStatus() });
  }

  /** seal/src/flows.rs `open`. */
  private open(challenge: Uint8Array, phoneKeyHex: string, pin: string | null) {
    const card = this.card;
    const uid = hexOf(card.uid);
    const journaled = this.serving.opens.get(uid);
    if (journaled !== undefined) {
      if (journaled !== phoneKeyHex) {
        throw new Refused('ERR_SEAL_REFUSED');
      }
    } else {
      if (card.state !== 'sealed') {
        throw new Refused('ERR_SEAL_WRONG_STATE');
      }
      if (card.pin) {
        if (pin === null) {
          throw new Refused('ERR_SEAL_PIN_REQUIRED');
        }
        if (card.tries === 0) {
          throw new Refused('ERR_SEAL_PIN_LOCKED');
        }
        // The try is counted on the card before the PIN is compared.
        card.tries -= 1;
        this.serving.pinTries += 1;
        if (pin !== card.pin) {
          throw new Refused('ERR_SEAL_WRONG_PIN');
        }
      }
      this.serving.opens.set(uid, phoneKeyHex);
      card.state = 'opening';
    }
    card.state = 'opened';
    card.generation += 1;
    card.keyPresent = false;
    // The fake release: magic, the hash of the phone key it is for, a stand-in body.
    const release = Uint8Array.from([0x47, 0x53, 0x52, 0x31, ...fakeHash(bytesOf(phoneKeyHex)), ...new Uint8Array(48).fill(0x2a)]);
    return {
      ...this.answer(3, challenge, { state: 3, coin: card.coin, amountWei: card.amountWei, binding: fakeHash(release) }),
      release,
    };
  }

  private async relay(
    name: string,
    kind: 1 | 2 | 3,
    run: (challenge: Uint8Array) => { answer: Uint8Array; signature: Uint8Array; commitData?: Uint8Array; release?: Uint8Array },
    url: string,
    request: Record<string, string>,
  ): Promise<NativeSealCheck & { commitData?: string }> {
    this.calls.push(name);
    // A home-region flow with no list sends nothing and opens no card sheet.
    const home = url === '';
    if (home && (!this.nativeRegions || this.nativeRegions.length === 0)) {
      throw new Refused('ERR_SEAL_UNREACHABLE');
    }
    if (this.gate) {
      await this.gate;
    }
    if (this.cancel) {
      throw new Refused('ERR_NFC_CANCELLED');
    }
    // The card's UID is read; the one Seal of this tap is chosen now, once.
    const region = home ? this.homeOf(this.nativeRegions!) : '';
    const seal = home ? this.sealOf(region) : this.seal;
    this.regionsUsed.push(region);
    this.serving = seal;
    seal.lastRequest = { ...request, region };
    if (seal.offline) {
      throw new Refused('ERR_SEAL_UNREACHABLE');
    }
    // The one start request of this tap.
    seal.starts += 1;
    if (seal.wrongRegion) {
      // Refused before any session, card command or journal write; the region it names is never followed.
      throw new Refused('ERR_SEAL_WRONG_REGION');
    }
    if (!this.card.ghost) {
      throw new Refused('ERR_SEAL_NOT_GHOST_CARD');
    }
    const challenge = Uint8Array.from({ length: 32 }, () => Math.floor(Math.random() * 256));
    this.challenges.push(challenge);
    const done = run(challenge);
    if (this.dropAfterFlow) {
      // The Seal finished the flow, but the card left the field before its answer came back.
      this.dropAfterFlow = false;
      throw new Refused('ERR_NFC_SESSION');
    }
    // As SealRelay.swift does before it resolves: an answer of this flow, over this challenge, about this card.
    if (
      done.answer.length !== 203 ||
      done.answer[20] !== kind ||
      !same(done.answer.slice(21, 53), challenge) ||
      !same(done.answer.slice(53, 60), this.card.uid)
    ) {
      throw new Refused('ERR_SEAL_BAD_ANSWER');
    }
    if (done.release) {
      // The release goes straight to the native core.
      if (this.core.takeRelease(done.release) !== 0) {
        throw new Refused('ERR_SEAL_BAD_ANSWER');
      }
    }
    return {
      uid: hexOf(this.card.uid),
      challenge: hexOf(challenge),
      answer: hexOf(done.answer),
      signature: hexOf(done.signature),
      rounds: [
        { kind: 'seal', ms: 40 },
        { kind: 'card', ms: 10 },
      ],
      totalMs: 50,
      region,
      ...(done.commitData ? { commitData: hexOf(done.commitData) } : {}),
    };
  }

  private makeNative(): GhostNfcSealNative & GhostNfcSealRegionsNative {
    return {
      isSupported: () => this.nfc,
      setSealRegions: (regionsJson) => {
        this.nativeRegions = JSON.parse(regionsJson) as SealRegionAddress[];
        return true;
      },
      relayCheck: (url) => this.relay('check', 1, (challenge) => this.check(challenge), url, { url }),
      relayFill: (url, _alert, amountWei, pin) =>
        this.relay('fill', 2, (challenge) => this.fill(challenge, BigInt(amountWei), pin === '' ? null : pin), url, {
          url,
          amountWei,
          pin,
        }) as Promise<NativeSealCheck & { commitData: string }>,
      relayFillConfirm: (url) => this.relay('confirm', 2, (challenge) => this.confirm(challenge), url, { url }),
      relayOpen: (url, _alert, phoneKey, pin) =>
        this.relay('open', 3, (challenge) => this.open(challenge, phoneKey, pin === '' ? null : pin), url, { url, phoneKey, pin }),
      keepOpenKey: () => {
        if (!this.core.phoneKey) {
          throw new Error('no phone key');
        }
        this.keychain = this.core.phoneKey.slice();
      },
      restoreOpenKey: () => {
        if (!this.keychain) {
          return false;
        }
        this.core.phoneKey ??= this.keychain.slice();
        return true;
      },
      forgetOpenKey: () => {
        this.keychain = null;
      },
    };
  }
}

/** The one world of a test file: the module mocks and the tests share it. */
export const world = { current: new World() };

export function resetWorld(): World {
  world.current = new World();
  return world.current;
}
