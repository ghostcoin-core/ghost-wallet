// The Seal relay as JavaScript sees it. The native relay is replaced by a
// double that does what ios/SealRelay.swift does: it drives a fake card
// against a fake Seal, carrying each command and each card answer as opaque
// bytes, and resolves with the UID, the challenge, the signed answer and the
// timings. The JavaScript surface must hand back only the result.
import fs from 'fs';
import path from 'path';

import { CardCancelled, type GhostNfcSealRegionsNative } from '../../modules/ghost-nfc';
import {
  checkWithSeal,
  confirmFillWithSeal,
  fillWithSeal,
  HOME_REGION,
  openWithSeal,
  readAnswerResult,
  readResult,
  RELAY_PROBLEMS,
  SealRelayError,
  setSealRegions,
  type GhostNfcRelayNative,
  type GhostNfcSealNative,
  type NativeSealCheck,
} from '../../modules/ghost-nfc/relay';

jest.mock('expo', () => ({ requireOptionalNativeModule: () => null }));

/** The region the double's native relay picks for a home-region flow. */
const HOME = 'eu-central-1';

const UID = Uint8Array.from([0x04, 0x51, 0x8d, 0xfa, 0xa9, 0x61, 0x80]);
const AMOUNT = 1_500_000_000_000_000_000n;
const SEAL_URL = 'https://seal.example:8443';

function hex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** A deterministic byte stream (test only). */
function stream(seed: number, length: number): Uint8Array {
  let x = seed >>> 0 || 1;
  return Uint8Array.from({ length }, () => {
    x ^= x << 13;
    x >>>= 0;
    x ^= x >>> 17;
    x ^= x << 5;
    x >>>= 0;
    return x & 0xff;
  });
}

/** A card that answers each command under a key only it and the Seal share. */
class FakeCard {
  readonly key = stream(7, 16);
  inField = true;
  /** Drop the card from this command on (counted from 0). */
  dropAt: number | null = null;
  seen = 0;

  answer(command: Uint8Array): Uint8Array | null {
    const index = this.seen++;
    if (!this.inField || (this.dropAt !== null && index >= this.dropAt)) {
      return null;
    }
    const body = command.map((byte, i) => byte ^ this.key[i % 16] ^ 0x5a);
    return Uint8Array.from([...body, 0x91, 0x00]);
  }
}

type SealReply = { status: 'command'; session: string; command: Uint8Array } | { status: 'done'; answer: Uint8Array; signature: Uint8Array };

/** A Seal that runs a seven-command Check and signs its answer (a stand-in signature). */
class FakeSeal {
  readonly key = stream(7, 16);
  refuse: string | null = null;
  state = 1;
  answerFor: { challenge?: Uint8Array; uid?: Uint8Array; length?: number } = {};
  private sessions = new Map<string, { uid: Uint8Array; challenge: Uint8Array; sent: Uint8Array; step: number }>();
  private counter = 0;

  start(uid: Uint8Array, challenge: Uint8Array): SealReply {
    if (this.refuse) {
      throw Object.assign(new Error(`refused after ${hex(stream(3, 8))}`), { code: this.refuse });
    }
    const session = hex(stream(100 + this.counter++, 16));
    const sent = stream(200 + this.counter, 24);
    this.sessions.set(session, { uid, challenge, sent, step: 1 });
    return { status: 'command', session, command: sent };
  }

  step(session: string, cardAnswer: Uint8Array): SealReply {
    const held = this.sessions.get(session);
    if (!held) {
      throw Object.assign(new Error('unknown or finished session'), { code: 'ERR_SEAL_REFUSED' });
    }
    const expected = held.sent.map((byte, i) => byte ^ this.key[i % 16] ^ 0x5a);
    if (hex(cardAnswer.slice(0, -2)) !== hex(expected)) {
      throw Object.assign(new Error('the card answered wrong'), { code: 'ERR_SEAL_REFUSED' });
    }
    if (held.step === 7) {
      this.sessions.delete(session);
      return { status: 'done', answer: this.signedAnswer(held.uid, held.challenge), signature: stream(9, 3309) };
    }
    held.step += 1;
    held.sent = stream(300 + held.step + this.counter, 24);
    return { status: 'command', session, command: held.sent };
  }

  private signedAnswer(uid: Uint8Array, challenge: Uint8Array): Uint8Array {
    const out = new Uint8Array(203);
    out.set(Array.from('ghost-seal/v1/answer', (c) => c.charCodeAt(0)), 0);
    out[20] = 1;
    out.set(this.answerFor.challenge ?? challenge, 21);
    out.set(this.answerFor.uid ?? uid, 53);
    out[144] = this.state;
    let amount = this.state === 0 ? 0n : AMOUNT;
    for (let i = 160; i >= 145; i -= 1) {
      out[i] = Number(amount & 0xffn);
      amount >>= 8n;
    }
    return this.answerFor.length ? out.slice(0, this.answerFor.length) : out;
  }
}

/** The native relay's double: everything it carries stays inside it. */
function relayDouble(card = new FakeCard(), seal = new FakeSeal()) {
  const traffic: Uint8Array[] = [];
  const calls: { url: string; alert: string }[] = [];
  let clock = 0;
  const tick = (ms: number) => {
    clock += ms;
    return ms;
  };
  const nfc: GhostNfcRelayNative & { cancelled: boolean; supported: boolean } = {
    cancelled: false,
    supported: true,
    isSupported() {
      return this.supported;
    },
    async relayCheck(url, alert) {
      calls.push({ url, alert });
      if (this.cancelled) {
        throw Object.assign(new Error('The card sheet was closed.'), { code: 'ERR_NFC_CANCELLED' });
      }
      const challenge = stream(42, 32);
      const rounds: { kind: string; ms: number }[] = [];
      const started = clock;
      let reply = seal.start(UID, challenge);
      rounds.push({ kind: 'seal', ms: tick(80) });
      while (reply.status === 'command') {
        traffic.push(reply.command);
        const answer = card.answer(reply.command);
        rounds.push({ kind: 'card', ms: tick(12) });
        if (answer === null) {
          throw Object.assign(new Error(`card gone after ${hex(reply.command)}`), { code: 'ERR_NFC_SESSION' });
        }
        traffic.push(answer);
        reply = seal.step(reply.session, answer);
        rounds.push({ kind: 'seal', ms: tick(85) });
      }
      return {
        uid: hex(UID),
        challenge: hex(challenge),
        answer: hex(reply.answer),
        signature: hex(reply.signature),
        rounds,
        totalMs: clock - started,
        // As SealRelay.swift does: the home region it chose, none for a typed address.
        region: url === '' ? HOME : '',
      };
    },
  };
  return { nfc, card, seal, traffic, calls };
}

function problemOf(promise: Promise<unknown>): Promise<string> {
  return promise.then(
    () => 'none',
    (error) => (error instanceof SealRelayError ? error.problem : `other: ${String(error)}`),
  );
}

describe('a Check through the Seal', () => {
  it('returns only the card UID, the state, the amount, the signed answer, the challenge and the timings', async () => {
    const { nfc, calls } = relayDouble();
    const result = await checkWithSeal(SEAL_URL, nfc);

    expect(Object.keys(result).sort()).toEqual([
      'amountWei',
      'answer',
      'challenge',
      'region',
      'rounds',
      'signature',
      'state',
      'totalMs',
      'uid',
    ]);
    // A typed address is that one Seal: no region.
    expect(result.region).toBe('');
    // The challenge the native relay made and sent: the answer's check needs it.
    expect(hex(result.challenge)).toBe(hex(stream(42, 32)));
    expect(result.uid).toBe('04518DFAA96180');
    expect(result.state).toBe('sealed');
    expect(result.amountWei).toBe(AMOUNT);
    expect(result.answer).toHaveLength(203);
    expect(result.signature).toHaveLength(3309);
    expect(calls).toEqual([{ url: SEAL_URL, alert: expect.any(String) }]);
  });

  it('records each round trip, labelled card or Seal, and the total', async () => {
    const { nfc } = relayDouble();
    const result = await checkWithSeal(SEAL_URL, nfc);

    expect(result.rounds.filter((round) => round.kind === 'card')).toHaveLength(7);
    expect(result.rounds.filter((round) => round.kind === 'seal')).toHaveLength(8);
    expect(result.rounds[0]).toEqual({ kind: 'seal', ms: 80 });
    expect(result.rounds[1]).toEqual({ kind: 'card', ms: 12 });
    expect(result.rounds.every((round) => Object.keys(round).sort().join() === 'kind,ms')).toBe(true);
    expect(result.totalMs).toBe(80 + 7 * (12 + 85));
  });

  it('never hands JavaScript a command or a card answer', async () => {
    const { nfc, traffic } = relayDouble();
    const result = await checkWithSeal(SEAL_URL, nfc);

    expect(traffic).toHaveLength(14);
    const seen = [result.uid, hex(result.answer), hex(result.signature), JSON.stringify(result.rounds)]
      .join('|')
      .toLowerCase();
    for (const bytes of traffic) {
      expect(seen).not.toContain(hex(bytes));
    }
  });

  it('reads the state and amount from the signed answer bytes', async () => {
    const seal = new FakeSeal();
    seal.state = 0;
    const { nfc } = relayDouble(new FakeCard(), seal);
    const result = await checkWithSeal(SEAL_URL, nfc);
    expect(result.state).toBe('empty');
    expect(result.amountWei).toBe(0n);
  });

  it('refuses an answer over another challenge, about another card, or cut short', async () => {
    for (const answerFor of [{ challenge: stream(43, 32) }, { uid: Uint8Array.from([4, 1, 2, 3, 4, 5, 6]) }, { length: 202 }]) {
      const seal = new FakeSeal();
      seal.answerFor = answerFor;
      const { nfc } = relayDouble(new FakeCard(), seal);
      expect(await problemOf(checkWithSeal(SEAL_URL, nfc))).toBe('bad-answer');
    }
  });

  it('keeps nothing extra the native side might add', () => {
    const { seal } = relayDouble();
    const challenge = stream(42, 32);
    let reply = seal.start(UID, challenge);
    const card = new FakeCard();
    while (reply.status === 'command') {
      reply = seal.step(reply.session, card.answer(reply.command)!);
    }
    const native = {
      uid: hex(UID),
      challenge: hex(challenge),
      answer: hex(reply.answer),
      signature: hex(reply.signature),
      rounds: [{ kind: 'seal', ms: 3, bytes: 'ff' }],
      totalMs: 3,
      region: '',
      extra: 'nothing',
    } as unknown as NativeSealCheck;
    const result = readResult(native);
    expect(Object.keys(result)).not.toContain('extra');
    expect(hex(result.challenge)).toBe(hex(challenge));
    expect(result.rounds).toEqual([{ kind: 'seal', ms: 3 }]);
    expect(() => readResult({ ...native, rounds: [{ kind: 'phone', ms: 1 }] })).toThrow(SealRelayError);
  });

  it('keeps the region on the answer, and refuses one that is malformed', () => {
    const { seal } = relayDouble();
    const challenge = stream(42, 32);
    let reply = seal.start(UID, challenge);
    const card = new FakeCard();
    while (reply.status === 'command') {
      reply = seal.step(reply.session, card.answer(reply.command)!);
    }
    const base = {
      uid: hex(UID),
      challenge: hex(challenge),
      answer: hex(reply.answer),
      signature: hex(reply.signature),
      rounds: [],
      totalMs: 3,
    };
    expect(readAnswerResult({ ...base, region: HOME }, 'check', true).region).toBe(HOME);
    expect(readAnswerResult({ ...base, region: '' }, 'check', false).region).toBe('');
    // A home-region flow must name a region id; a typed address none.
    for (const region of ['', 'EU-CENTRAL-1', 'eu central', 'a'.repeat(33), 'eu-central-1\n', undefined, 7, null]) {
      expect(() => readAnswerResult({ ...base, region } as unknown as NativeSealCheck, 'check', true)).toThrow(SealRelayError);
    }
    for (const region of [HOME, undefined, 0]) {
      expect(() => readAnswerResult({ ...base, region } as unknown as NativeSealCheck, 'check')).toThrow(SealRelayError);
    }
  });
});

describe('a flow sent to the card\'s home region', () => {
  it('goes to the native relay with an empty address, and names the region it ran in', async () => {
    expect(HOME_REGION).toBe('');
    const { nfc, calls } = relayDouble();
    const result = await checkWithSeal(HOME_REGION, nfc);
    expect(calls).toEqual([{ url: '', alert: expect.any(String) }]);
    expect(result.region).toBe(HOME);
    expect(result.state).toBe('sealed');
  });

  it('refuses a native result that names no region', async () => {
    const { nfc } = relayDouble();
    const relayCheck = nfc.relayCheck.bind(nfc);
    nfc.relayCheck = async (url, alert) => ({ ...(await relayCheck(url, alert)), region: '' });
    expect(await problemOf(checkWithSeal(HOME_REGION, nfc))).toBe('bad-answer');
  });

  it('a blank address is not the home region: only the empty string is', async () => {
    const { nfc, calls } = relayDouble();
    expect(await problemOf(checkWithSeal(' ', nfc))).toBe('bad-address');
    expect(calls).toHaveLength(0);
  });
});

describe('setSealRegions', () => {
  function regionsNative(answer = true) {
    const lists: string[] = [];
    const nfc: GhostNfcSealRegionsNative = {
      setSealRegions: (json) => {
        lists.push(json);
        return answer;
      },
    };
    return { nfc, lists };
  }

  const THREE = [
    { id: 'us-east-1', url: 'https://us-east-1.seal.example' },
    { id: 'eu-central-1', url: 'https://eu-central-1.seal.example' },
    { id: 'ap-southeast-1', url: 'https://ap-southeast-1.seal.example' },
  ];

  it('hands the native relay the ordered list as JSON, ids and addresses only', () => {
    const { nfc, lists } = regionsNative();
    const extra = THREE.map((r) => ({ ...r, note: 'not sent' }));
    expect(setSealRegions(extra, nfc)).toBe(true);
    expect(lists).toEqual([JSON.stringify(THREE)]);
    expect(setSealRegions([], nfc)).toBe(true);
    expect(lists[1]).toBe('[]');
  });

  it('clears the native list instead for a bad id, a duplicate or an address that is not https://', () => {
    for (const bad of [
      [{ id: '', url: 'https://seal.example' }],
      [{ id: 'Us-East', url: 'https://seal.example' }],
      [THREE[0], { ...THREE[1], id: 'us-east-1' }],
      [{ id: 'us-east-1', url: 'http://seal.example' }],
      [{ id: 'us-east-1', url: 'seal.example' }],
    ]) {
      const { nfc, lists } = regionsNative();
      expect(setSealRegions(bad, nfc)).toBe(false);
      expect(lists).toEqual(['[]']);
    }
  });

  it('is false with no module, or when the native side refuses or throws', () => {
    expect(setSealRegions(THREE, null)).toBe(false);
    expect(setSealRegions(THREE)).toBe(false);
    expect(setSealRegions(THREE, regionsNative(false).nfc)).toBe(false);
    expect(
      setSealRegions(THREE, {
        setSealRegions: () => {
          throw new Error('refused');
        },
      }),
    ).toBe(false);
  });
});

describe('a failed relay', () => {
  it('maps a Seal refusal to a plain error, without the native details', async () => {
    const seal = new FakeSeal();
    seal.refuse = 'ERR_SEAL_REFUSED';
    const { nfc } = relayDouble(new FakeCard(), seal);
    const error = await checkWithSeal(SEAL_URL, nfc).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SealRelayError);
    expect((error as SealRelayError).problem).toBe('seal-refused');
    expect((error as Error).message).toBe(RELAY_PROBLEMS['seal-refused']);
    expect((error as Error).message).not.toMatch(/[0-9a-f]{8}/);
  });

  it('says the card moved away when it leaves the field mid-Check', async () => {
    const card = new FakeCard();
    card.dropAt = 3;
    const { nfc } = relayDouble(card);
    const error = await checkWithSeal(SEAL_URL, nfc).catch((e: unknown) => e);
    expect((error as SealRelayError).problem).toBe('card-lost');
    expect((error as Error).message).toBe('The card moved away. Hold it still and try again.');
  });

  it('maps each native failure to its problem, and anything unknown to a plain failure', async () => {
    const cases: [string, string][] = [
      ['ERR_SEAL_EXPIRED', 'session-expired'],
      ['ERR_SEAL_UNREACHABLE', 'seal-unreachable'],
      ['ERR_SEAL_BAD_ANSWER', 'bad-answer'],
      ['ERR_SEAL_RELAY_BUSY', 'busy'],
      ['ERR_NFC_UNAVAILABLE', 'no-nfc'],
      ['ERR_SOMETHING_ELSE', 'failed'],
    ];
    for (const [code, problem] of cases) {
      const seal = new FakeSeal();
      seal.refuse = code;
      const { nfc } = relayDouble(new FakeCard(), seal);
      expect(await problemOf(checkWithSeal(SEAL_URL, nfc))).toBe(problem);
    }
  });

  it('reports a closed card sheet as cancelled', async () => {
    const { nfc } = relayDouble();
    nfc.cancelled = true;
    await expect(checkWithSeal(SEAL_URL, nfc)).rejects.toBeInstanceOf(CardCancelled);
  });

  it('refuses a bad Seal address, or no NFC, before opening the card sheet', async () => {
    const { nfc, calls } = relayDouble();
    // The empty address is the card's home region (below), not a bad one.
    for (const address of [' ', 'seal.example', 'ftp://seal.example', 'https://']) {
      expect(await problemOf(checkWithSeal(address, nfc))).toBe('bad-address');
    }
    expect(await problemOf(checkWithSeal(SEAL_URL, null))).toBe('no-nfc');
    nfc.supported = false;
    expect(await problemOf(checkWithSeal(SEAL_URL, nfc))).toBe('no-nfc');
    expect(calls).toHaveLength(0);
  });
});

describe('a Fill and an Open through the Seal', () => {
  /** A signed answer of `kind` over `challenge` (a stand-in signature). */
  function answerOf(kind: number, challenge: Uint8Array): string {
    const out = new Uint8Array(203);
    out.set(Array.from('ghost-seal/v1/answer', (c) => c.charCodeAt(0)), 0);
    out[20] = kind;
    out.set(challenge, 21);
    out.set(UID, 53);
    return hex(out);
  }

  function sealNative(kindOf: { fill: number; open: number } = { fill: 2, open: 3 }) {
    const challenge = stream(77, 32);
    const calls: unknown[][] = [];
    const base = { uid: hex(UID), challenge: hex(challenge), signature: hex(stream(9, 3309)), rounds: [], totalMs: 5, region: '' };
    const nfc: GhostNfcSealNative = {
      isSupported: () => true,
      relayCheck: async () => ({ ...base, answer: answerOf(1, challenge) }),
      relayFill: async (...args) => {
        calls.push(['fill', ...args]);
        return { ...base, answer: answerOf(kindOf.fill, challenge), commitData: hex(stream(5, 430)) };
      },
      relayFillConfirm: async (...args) => {
        calls.push(['confirm', ...args]);
        return { ...base, answer: answerOf(kindOf.fill, challenge) };
      },
      relayOpen: async (...args) => {
        calls.push(['open', ...args]);
        return { ...base, answer: answerOf(kindOf.open, challenge) };
      },
      keepOpenKey: () => {},
      restoreOpenKey: () => false,
      forgetOpenKey: () => {},
    };
    return { nfc, calls, challenge };
  }

  it('fills with the amount and PIN, and hands back the commit data and the challenge', async () => {
    const { nfc, calls, challenge } = sealNative();
    const filled = await fillWithSeal(SEAL_URL, AMOUNT, '1234', nfc);
    expect(calls).toEqual([['fill', SEAL_URL, expect.any(String), AMOUNT.toString(), '1234']]);
    expect(filled.commitData).toHaveLength(430);
    expect(hex(filled.challenge)).toBe(hex(challenge));
    await fillWithSeal(SEAL_URL, AMOUNT, null, nfc);
    expect(calls[1][4]).toBe('');
  });

  it('never sends a PIN that is not 4 to 8 digits', async () => {
    const { nfc, calls } = sealNative();
    for (const pin of ['123', '123456789', '12a4']) {
      expect(await problemOf(fillWithSeal(SEAL_URL, AMOUNT, pin, nfc))).toBe('wrong-pin');
    }
    expect(calls).toHaveLength(0);
  });

  it('opens to the phone key as hex, and refuses an answer of another flow', async () => {
    const { nfc, calls } = sealNative();
    const phoneKey = stream(3, 1184);
    const opened = await openWithSeal(SEAL_URL, phoneKey, null, nfc);
    expect(calls).toEqual([['open', SEAL_URL, expect.any(String), hex(phoneKey), '']]);
    expect(Object.keys(opened)).not.toContain('release');
    expect(await problemOf(openWithSeal(SEAL_URL, stream(3, 100), null, nfc))).toBe('failed');

    const swapped = sealNative({ fill: 3, open: 1 });
    expect(await problemOf(openWithSeal(SEAL_URL, phoneKey, null, swapped.nfc))).toBe('bad-answer');
    expect(await problemOf(fillWithSeal(SEAL_URL, AMOUNT, null, swapped.nfc))).toBe('bad-answer');
    expect(await problemOf(confirmFillWithSeal(SEAL_URL, swapped.nfc))).toBe('bad-answer');
  });

  it('maps the Seal refusal reasons of a Sealed card', async () => {
    const cases: [string, string][] = [
      ['ERR_SEAL_NOT_GHOST_CARD', 'not-a-ghost-card'],
      ['ERR_SEAL_FILLING', 'filling'],
      ['ERR_SEAL_CANT_CHECK', 'cant-check-now'],
      ['ERR_SEAL_PIN_REQUIRED', 'pin-required'],
      ['ERR_SEAL_WRONG_PIN', 'wrong-pin'],
      ['ERR_SEAL_PIN_LOCKED', 'pin-locked'],
      ['ERR_SEAL_SPENT', 'spent'],
      ['ERR_SEAL_WRONG_REGION', 'wrong-region'],
    ];
    for (const [code, problem] of cases) {
      const { nfc } = sealNative();
      nfc.relayOpen = async () => {
        throw Object.assign(new Error('refused'), { code });
      };
      expect(await problemOf(openWithSeal(SEAL_URL, stream(3, 1184), '1234', nfc))).toBe(problem);
    }
  });

  it('runs a Fill, a confirmation and an Open in the home region, and keeps the region each names', async () => {
    const { nfc, calls } = sealNative();
    // As SealRelay.swift answers a flow sent with an empty address: naming the home region it chose.
    const { relayFill, relayFillConfirm, relayOpen } = nfc;
    nfc.relayFill = async (...args) => ({ ...(await relayFill(...args)), region: HOME });
    nfc.relayFillConfirm = async (...args) => ({ ...(await relayFillConfirm(...args)), region: HOME });
    nfc.relayOpen = async (...args) => ({ ...(await relayOpen(...args)), region: HOME });
    expect((await fillWithSeal(HOME_REGION, AMOUNT, null, nfc)).region).toBe(HOME);
    expect((await confirmFillWithSeal(HOME_REGION, nfc)).region).toBe(HOME);
    expect((await openWithSeal(HOME_REGION, stream(3, 1184), null, nfc)).region).toBe(HOME);
    expect(calls.map((call) => call[1])).toEqual(['', '', '']);
    // The same native results against a typed address name a region they must not.
    expect(await problemOf(fillWithSeal(SEAL_URL, AMOUNT, null, nfc))).toBe('bad-answer');
  });

  it('says plainly that a card served by another region needs an update, and nothing the Seal sent', async () => {
    expect(RELAY_PROBLEMS['wrong-region']).toBe(
      'This card is served by another Seal region than the one this iPhone chose. Update Ghost Wallet, then try again.',
    );
    const { nfc, calls } = sealNative();
    nfc.relayCheck = async () => {
      throw Object.assign(new Error('The Seal refused the card: ap-southeast-1'), { code: 'ERR_SEAL_WRONG_REGION', homeRegion: 'ap-southeast-1' });
    };
    const error = await checkWithSeal(HOME_REGION, nfc).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(SealRelayError);
    expect((error as SealRelayError).problem).toBe('wrong-region');
    expect((error as Error).message).toBe(RELAY_PROBLEMS['wrong-region']);
    expect((error as Error).message).not.toMatch(/ap-southeast/);
    expect(calls).toHaveLength(0);
  });
});

describe('the relay module', () => {
  const source = fs.readFileSync(path.join(__dirname, '..', '..', 'modules', 'ghost-nfc', 'relay.ts'), 'utf8');

  it('neither mentions a card command nor sends one itself', () => {
    expect(source).not.toMatch(/apdu/i);
    expect(source).not.toMatch(/transceive/);
  });

  it('gives JavaScript one relay function and no way to read card traffic', () => {
    const type = source.match(/export type GhostNfcRelayNative = \{([\s\S]*?)\n\};/);
    expect(type).not.toBeNull();
    const members = [...type![1].matchAll(/^\s+(\w+)\(/gm)].map((m) => m[1]).sort();
    expect(members).toEqual(['isSupported', 'relayCheck']);
  });
});
