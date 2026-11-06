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
// Open's release to the core, never to JavaScript.
import type { SealBindings, CoreSealAnswerCheck, CoreSealAnswerVerdict } from '../../modules/ghost-core';
import type { GhostNfcSealNative, NativeSealCheck } from '../../modules/ghost-nfc/relay';

export const FAKE_MEASUREMENT_HEX = '5e'.repeat(48);
export const OTHER_MEASUREMENT_HEX = '6f'.repeat(48);
export const FAKE_SEAL_URL = 'https://seal.example:8443';
export const UID_HEX = '04518DFAA96180';
export const GHOST = 10n ** 18n;

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
export function fakeHash(data: Uint8Array, salt = 0): Uint8Array {
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
  native: GhostNfcSealNative;
  calls: string[] = [];
  /** Run before a flow resolves, to hold it (the spinner tests). */
  gate: Promise<void> | null = null;
  /** The next flow finishes on the Seal, but its answer never reaches the phone. */
  dropAfterFlow = false;

  constructor() {
    this.native = this.makeNative();
  }

  trusted() {
    return this.noSeal ? null : { url: FAKE_SEAL_URL, verifyingKey: this.seal.key, measurement: this.seal.measurement };
  }

  /** Puts a fresh card, set up and empty, in the field. */
  newCard(): FakeCard {
    this.card = new FakeCard();
    return this.card;
  }

  /** Makes the card Sealed with `amountWei`, as a confirmed Fill leaves it. */
  sealedCard(amountWei: bigint, pin: string | null = null): FakeCard {
    const card = this.newCard();
    card.state = 'sealed';
    card.keyPresent = true;
    card.amountWei = amountWei;
    card.coin = fakeHash(Uint8Array.from([1, 2, 3]));
    card.pin = pin;
    card.tries = pin ? 5 : 0;
    this.seal.paid = true;
    return card;
  }

  private answer(kind: 1 | 2 | 3, challenge: Uint8Array, fields: Partial<Body>): { answer: Uint8Array; signature: Uint8Array } {
    const seal = this.seal;
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
    const journaled = this.seal.opens.get(hexOf(card.uid));
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
    if (this.seal.chainDown) {
      throw new Refused('ERR_SEAL_CANT_CHECK');
    }
    if (this.seal.spent) {
      throw new Refused('ERR_SEAL_SPENT');
    }
    if (!this.seal.paid) {
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
    let pending = this.seal.fills.get(uid);
    if (card.keyPresent) {
      if (!pending || pending.amountWei !== amountWei || pending.pin !== pin) {
        throw new Refused('ERR_SEAL_FILL_PENDING');
      }
    } else {
      const n = this.seal.fills.size + 1;
      pending = { commitData: new Uint8Array(430).map((_, i) => (i * 7 + n) & 0xff), amountWei, pin };
      this.seal.fills.set(uid, pending);
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
    const journaled = this.seal.opens.get(uid);
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
        this.seal.pinTries += 1;
        if (pin !== card.pin) {
          throw new Refused('ERR_SEAL_WRONG_PIN');
        }
      }
      this.seal.opens.set(uid, phoneKeyHex);
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
  ): Promise<NativeSealCheck & { commitData?: string }> {
    this.calls.push(name);
    if (this.gate) {
      await this.gate;
    }
    if (this.cancel) {
      throw new Refused('ERR_NFC_CANCELLED');
    }
    if (this.seal.offline) {
      throw new Refused('ERR_SEAL_UNREACHABLE');
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
      ...(done.commitData ? { commitData: hexOf(done.commitData) } : {}),
    };
  }

  private makeNative(): GhostNfcSealNative {
    return {
      isSupported: () => this.nfc,
      relayCheck: (url) => {
        this.seal.lastRequest = { url };
        return this.relay('check', 1, (challenge) => this.check(challenge));
      },
      relayFill: (url, _alert, amountWei, pin) => {
        this.seal.lastRequest = { url, amountWei, pin };
        return this.relay('fill', 2, (challenge) => this.fill(challenge, BigInt(amountWei), pin === '' ? null : pin)) as Promise<
          NativeSealCheck & { commitData: string }
        >;
      },
      relayFillConfirm: (url) => {
        this.seal.lastRequest = { url };
        return this.relay('confirm', 2, (challenge) => this.confirm(challenge));
      },
      relayOpen: (url, _alert, phoneKey, pin) => {
        this.seal.lastRequest = { url, phoneKey, pin };
        return this.relay('open', 3, (challenge) => this.open(challenge, phoneKey, pin === '' ? null : pin));
      },
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
