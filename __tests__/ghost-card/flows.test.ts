// The Ghost card flows (lib/ghost-card/flows.ts) against a fake card and a
// fake native core: what each tap is sent, what each verdict and chain state
// is shown as, and every refusal. The core's own checks of certificates,
// statements and Open releases are tested in Rust against the card's real
// answers (core/tests/java_card.rs).
import type { CoreJavaCardStatement, CoreJavaCardVerdict, JavaCardBindings } from '../../modules/ghost-core';
import { CardCancelled } from '../../modules/ghost-nfc';
import { cardFailure, readTap, type GhostCardNative, type NativeTap } from '../../modules/ghost-nfc/java-card';
import type { CoinOnChain } from '../../lib/ghost-card/chain';
import {
  beBytes,
  checkGhostCard,
  fillGhostCard,
  openCodeGroups,
  openGhostCard,
  refillGhostCard,
  type GhostCardDeps,
} from '../../lib/ghost-card/flows';
import { ghostStatusText, safeToAccept } from '../../lib/ghost-card/status';

const CHAIN = 6_777_971n;
const hex = (n: number, byte = 0xab) => Array.from({ length: n }, () => byte.toString(16).padStart(2, '0')).join('');
const buf = (n: number, byte = 0) => new Uint8Array(n).fill(byte).buffer as ArrayBuffer;

function identify(state: number, fill = 1): string {
  return '0101' + state.toString(16).padStart(2, '0') + hex(16, 0x11) + fill.toString(16).padStart(8, '0') + '03e8' + '0400' + '1f36';
}

function statement(over: Partial<CoreJavaCardStatement> = {}): CoreJavaCardStatement {
  return {
    cardId: buf(16, 0x11),
    cardNumber: 'CEIR CEIR',
    state: 'sealed',
    fill: 1,
    chainId: CHAIN,
    amountWei: '5000000000000000000',
    commitment: buf(32, 0xc0),
    digest: buf(32, 0xd0),
    marker: buf(32, 0xe0),
    checksLeft: 1000,
    openCode: 'not-asked',
    batch: 1,
    devIssuer: true,
    leaf: { commitment: buf(32, 0xc0), note: buf(380, 0x40), salt: buf(16, 0x50) },
    ...over,
  };
}

type Calls = { name: string; args: unknown[] }[];

function fakeCore(verdict: () => CoreJavaCardVerdict, calls: Calls, finish = ''): JavaCardBindings {
  let n = 0;
  return {
    javaCardRandom: () => buf(32, ++n),
    javaCardNewOpenCode: () => 'A'.repeat(32),
    javaCardOpenCode: (text: string) => {
      if (text.replace(/\s/g, '').length !== 32) {
        throw new Error('not-an-open-code');
      }
      return buf(20, 0x77);
    },
    javaCardCodeHash: () => buf(32, 0x99),
    javaCardCodeConfirmation: () => buf(32, 0x98),
    javaCardNumber: () => 'CEIR CEIR',
    javaCardIdentity: (answer: ArrayBuffer) => {
      const b = new Uint8Array(answer);
      return {
        phase: b[1],
        state: ['blank', 'sealed', 'opened'][b[2]],
        cardId: answer.slice(3, 19),
        cardNumber: 'CEIR CEIR',
        fill: new DataView(answer).getUint32(19),
        checksLeft: 1000,
        certificateBytes: 7990,
      };
    },
    verifyJavaCardCheck: (input) => {
      calls.push({ name: 'verify', args: [input] });
      return verdict();
    },
    finishJavaCardOpen: (expect) => {
      calls.push({ name: 'finish', args: [expect] });
      return finish;
    },
    finishJavaCardOpenUnchecked: (cardId, fill) => {
      calls.push({ name: 'finish-unchecked', args: [cardId, fill] });
      return finish;
    },
    hasJavaCardRelease: () => false,
    forgetJavaCardRelease: () => {
      calls.push({ name: 'forget-release', args: [] });
    },
  };
}

function ghostTap(over: NativeTap = {}): NativeTap {
  return {
    kind: 'ghost',
    identify: identify(1),
    certificate: hex(7990),
    statement: hex(194),
    signature: hex(2508),
    ms: 2100,
    checkMs: 1900,
    reconnects: 0,
    ...over,
  };
}

function fakeNative(answer: () => NativeTap | Promise<NativeTap>, calls: Calls): GhostCardNative {
  const record = (name: string) => async (...args: unknown[]) => {
    calls.push({ name, args });
    return answer();
  };
  return {
    javaCardCheck: record('check'),
    javaCardFill: record('fill'),
    javaCardOpen: record('open'),
    javaCardRefill: record('refill'),
  };
}

function deps(
  tap: () => NativeTap | Promise<NativeTap>,
  verdict: () => CoreJavaCardVerdict,
  chain: CoinOnChain | Error = { status: 'buried', spent: false, leaf: statement().leaf ?? null },
  finish = '',
): GhostCardDeps & { calls: Calls } {
  const calls: Calls = [];
  return {
    calls,
    core: fakeCore(verdict, calls, finish),
    nfc: fakeNative(tap, calls),
    chainId: CHAIN,
    coinOnChain: async () => {
      calls.push({ name: 'chain', args: [] });
      if (chain instanceof Error) {
        throw chain;
      }
      return chain;
    },
  };
}

const ok = (over: Partial<CoreJavaCardStatement> = {}) => () => ({ refusal: '', statement: statement(over) });

describe('Check', () => {
  it('shows a genuine sealed card whose coin is buried and unspent as Sealed, with its fill and amount', async () => {
    const d = deps(() => ghostTap({ commitData: hex(430) }), ok());
    const result = await checkGhostCard(d);
    expect(result?.status).toEqual({
      kind: 'sealed',
      fill: 1,
      amountWei: 5n * 10n ** 18n,
      checksLeft: 1000,
      cardNumber: 'CEIR CEIR',
      codeConfirmed: false,
    });
    expect(ghostStatusText(result!.status)).toBe('Sealed (fill 1): holds 5 GHOST');
    expect(safeToAccept(result!.status)).toBe(true);
    // The tap asked for the commit data, with no code confirmation.
    expect(d.calls[0]).toMatchObject({ name: 'check', args: [expect.any(String), expect.any(Uint8Array), null, true] });
    // And the core was given what the card said, with this tap's challenge and chain.
    const input = d.calls[1].args[0] as { challenge: ArrayBuffer; chainId: bigint; commitData?: ArrayBuffer };
    expect(new Uint8Array(input.challenge)).toEqual(d.calls[0].args[1]);
    expect(input.chainId).toBe(CHAIN);
    expect(input.commitData?.byteLength).toBe(430);
    expect(result?.commitData?.length).toBe(430);
  });

  it('sends an open-code confirmation when a code is given, and says when the card confirmed it', async () => {
    const d = deps(() => ghostTap(), ok({ openCode: 'right' }));
    const result = await checkGhostCard(d, new Uint8Array(20));
    expect(d.calls[0].args[2]).toEqual(new Uint8Array(32).fill(0x98));
    expect(result?.status).toMatchObject({ kind: 'sealed', codeConfirmed: true });
  });

  it.each([
    ['a wrong open code', ok({ openCode: 'wrong' }), undefined, 'Open code wrong: not safe to accept'],
    ['a blank card', ok({ state: 'blank', fill: 3 }), undefined, 'Blank (fill 3): holds nothing'],
    ['an opened card', ok({ state: 'opened' }), undefined, 'Opened: not safe to accept'],
    ['a coin not on chain', ok(), { status: 'absent', spent: false, leaf: null }, 'Not on the chain yet: not safe to accept'],
    ['a coin still settling', ok(), { status: 'settling', spent: false, leaf: statement().leaf }, 'Settling (fill 1): not safe to accept yet'],
    ['a coin spent while sealed', ok(), { status: 'buried', spent: true, leaf: statement().leaf }, 'Spent while sealed: not safe to accept'],
    ['a failed signature', () => ({ refusal: 'statement-signature' }), undefined, 'Not a genuine Ghost card: not safe to accept'],
    ['an unknown issuer', () => ({ refusal: 'unknown-issuer' }), undefined, 'Not a genuine Ghost card: not safe to accept'],
    ['no chain', ok(), new Error('down'), "Can't check the chain right now"],
  ] as const)('shows %s as not safe', async (_name, verdict, chain, text) => {
    const d = deps(() => ghostTap({ commitData: hex(430) }), verdict, chain as CoinOnChain | Error | undefined);
    const result = await checkGhostCard(d);
    expect(ghostStatusText(result!.status)).toBe(text);
    expect(safeToAccept(result!.status)).toBe(false);
  });

  it('refuses a coin on chain whose note is not the card’s commit data', async () => {
    const other = { commitment: buf(32, 0xc0), note: buf(380, 0x41), salt: buf(16, 0x50) };
    const d = deps(() => ghostTap({ commitData: hex(430) }), ok(), { status: 'buried', spent: false, leaf: other });
    expect((await checkGhostCard(d))?.status.kind).toBe('not-on-chain');
  });

  it('tells an NTAG 424 card apart: Carry to Claim, and nothing is verified', async () => {
    const d = deps(() => ({ kind: 'ntag' }), ok());
    const result = await checkGhostCard(d);
    expect(ghostStatusText(result!.status)).toBe('Carry to Claim: not safe to accept');
    expect(d.calls.map((c) => c.name)).toEqual(['check']);
  });

  it('gives null when the sheet was closed, and a retry when the card moved', async () => {
    expect(await checkGhostCard(deps(() => Promise.reject({ code: 'ERR_NFC_CANCELLED' }), ok()))).toBeNull();
    const moved = await checkGhostCard(deps(() => Promise.reject({ code: 'ERR_NFC_SESSION' }), ok()));
    expect(moved?.status.kind).toBe('retry');
  });

  it('refuses parts of the wrong size before the core sees them', async () => {
    const d = deps(() => ghostTap({ statement: hex(193) }), ok());
    expect((await checkGhostCard(d))?.status).toEqual({ kind: 'not-genuine', reason: 'bad-answer' });
    expect(d.calls.map((c) => c.name)).toEqual(['check']);
  });
});

describe('Fill', () => {
  const make = (fill = 2, commitment = 0xc0) => fill.toString(16).padStart(8, '0') + hex(32, commitment) + hex(430, 0x33);
  const sealed2 = ok({ fill: 2, commitment: buf(32, 0xc0), openCode: 'right' });

  it('sends Make the amount, chain, a fresh nonce and the code’s hash, and pays only checked commit data', async () => {
    const d = deps(() => ghostTap({ identify: identify(1, 2), make: make() }), sealed2);
    const result = await fillGhostCard(d, 5n * 10n ** 18n, new Uint8Array(20).fill(0x77));
    expect(result).toMatchObject({ ok: true, fill: 2, amountWei: 5n * 10n ** 18n, cardNumber: 'CEIR CEIR' });
    const [, input, challenge, confirmation] = d.calls[0].args as [string, Uint8Array, Uint8Array, Uint8Array];
    expect(input.slice(0, 12)).toEqual(beBytes(5n * 10n ** 18n, 12));
    expect(input.slice(12, 20)).toEqual(beBytes(CHAIN, 8));
    expect(input.slice(52, 84)).toEqual(new Uint8Array(32).fill(0x99));
    expect(input.slice(20, 52)).not.toEqual(challenge);
    expect(confirmation).toEqual(new Uint8Array(32).fill(0x98));
    // The commit data verified is exactly what Make returned.
    const verified = d.calls[1].args[0] as { commitData: ArrayBuffer };
    expect(new Uint8Array(verified.commitData)).toEqual(new Uint8Array(430).fill(0x33));
    if (result.ok) {
      expect(result.commitData).toEqual(new Uint8Array(430).fill(0x33));
    }
  });

  it.each([
    ['not sealed', ok({ state: 'blank', fill: 2, openCode: 'right' }), 'fill-not-sealed'],
    ['another fill', ok({ fill: 3, openCode: 'right' }), 'fill-other-fill'],
    ['another commitment', ok({ fill: 2, commitment: buf(32, 0xc1), openCode: 'right' }), 'fill-other-commitment'],
    ['another amount', ok({ fill: 2, amountWei: '1', openCode: 'right' }), 'fill-other-amount'],
    ['another chain', ok({ fill: 2, chainId: 1n, openCode: 'right' }), 'fill-other-chain'],
    ['the code not confirmed', ok({ fill: 2, openCode: 'not-asked' }), 'fill-code-not-confirmed'],
    ['a refused statement', () => ({ refusal: 'commit-data-digest' }), 'commit-data-digest'],
  ] as const)('pays nothing for a statement with %s', async (_name, verdict, reason) => {
    const d = deps(() => ghostTap({ identify: identify(1, 2), make: make() }), verdict);
    expect(await fillGhostCard(d, 5n * 10n ** 18n, new Uint8Array(20))).toEqual({
      ok: false,
      status: { kind: 'not-genuine', reason },
    });
  });

  it('takes the commitment from the statement when the Make answer was lost and read back', async () => {
    const d = deps(() => ghostTap({ identify: identify(1, 2), make: make(2, 0) }), sealed2);
    expect((await fillGhostCard(d, 5n * 10n ** 18n, new Uint8Array(20))).ok).toBe(true);
  });

  it('says a card that is not blank is not in the state for it', async () => {
    const d = deps(() => Promise.reject({ code: 'ERR_GHOST_CARD_STATE', message: 'The card is sealed, so this cannot be done with it.' }), ok());
    const result = await fillGhostCard(d, 1n, new Uint8Array(20));
    expect(result).toEqual({ ok: false, status: { kind: 'retry', message: 'The card is not in the state this needs.' } });
  });
});

describe('Open', () => {
  it('checks the statement, then has the core recompute the coin from the card’s commit data', async () => {
    const d = deps(() => ghostTap({ commitData: hex(430), opened: true }), ok({ openCode: 'right' }));
    const result = await openGhostCard(d, new Uint8Array(20).fill(0x77));
    expect(result).toMatchObject({ ok: true, amountWei: 5n * 10n ** 18n, fill: 1 });
    const [, code, checkChallenge, confirmation, openChallenge] = d.calls[1].args as Uint8Array[];
    expect(code).toEqual(new Uint8Array(20).fill(0x77));
    expect(checkChallenge).not.toEqual(openChallenge);
    expect(confirmation).toEqual(new Uint8Array(32).fill(0x98));
    const finish = d.calls.find((c) => c.name === 'finish')!.args[0] as { salt: ArrayBuffer; note: ArrayBuffer; fill: number };
    expect(finish.fill).toBe(1);
    expect(new Uint8Array(finish.salt)).toEqual(new Uint8Array(16).fill(0x50));
    expect(new Uint8Array(finish.note)).toEqual(new Uint8Array(380).fill(0x40));
    // No chain read was needed: the commit data came with the tap.
    expect(d.calls.some((c) => c.name === 'chain')).toBe(false);
  });

  it('takes the salt and note from the chain for a card already opened', async () => {
    const leaf = { commitment: buf(32, 0xc0), note: buf(380, 0x42), salt: buf(16, 0x52) };
    const d = deps(() => ghostTap({ identify: identify(2), opened: true }), ok({ state: 'opened', openCode: 'right', leaf: undefined }), {
      status: 'buried',
      spent: false,
      leaf,
    });
    expect((await openGhostCard(d, new Uint8Array(20))).ok).toBe(true);
    const finish = d.calls.find((c) => c.name === 'finish')!.args[0] as { note: ArrayBuffer };
    expect(new Uint8Array(finish.note)).toEqual(new Uint8Array(380).fill(0x42));
  });

  it('says Open code wrong, and opens nothing, when the card says the code is wrong', async () => {
    const d = deps(() => ghostTap({ opened: false }), ok({ openCode: 'wrong' }));
    expect(await openGhostCard(d, new Uint8Array(20))).toEqual({ ok: false, status: { kind: 'code-wrong', cardNumber: 'CEIR CEIR' } });
    expect(d.calls.some((c) => c.name === 'finish')).toBe(false);
  });

  it('holds nothing when the core finds the release is not the card’s coin', async () => {
    const d = deps(() => ghostTap({ commitData: hex(430), opened: true }), ok({ openCode: 'right' }), undefined, 'open-not-the-coin');
    expect(await openGhostCard(d, new Uint8Array(20))).toEqual({
      ok: false,
      status: { kind: 'not-genuine', reason: 'open-not-the-coin' },
    });
  });

  it('wipes the release when the statement fails', async () => {
    const d = deps(() => ghostTap({ commitData: hex(430), opened: true }), () => ({ refusal: 'statement-signature' }));
    expect((await openGhostCard(d, new Uint8Array(20))).ok).toBe(false);
    expect(d.calls.filter((c) => c.name === 'forget-release').length).toBe(2);
    expect(d.calls.some((c) => c.name === 'finish')).toBe(false);
  });

  it('opens a card with no seal checks left with the chain as its only check', async () => {
    const d = deps(() => ghostTap({ statement: undefined, signature: undefined, opened: true }), ok());
    const result = await openGhostCard(d, new Uint8Array(20));
    expect(result).toMatchObject({ ok: true, amountWei: null, fill: 1 });
    expect(d.calls.find((c) => c.name === 'finish-unchecked')?.args[1]).toBe(1);
  });
});

describe('Refill', () => {
  it('gives the card’s new blank fill', async () => {
    const d = deps(() => ghostTap({ identify: identify(0, 4) }), ok());
    expect(await refillGhostCard(d, new Uint8Array(20))).toEqual({ ok: true, fill: 4, ms: 2100 });
  });

  it('says Open code wrong for a wrong code', async () => {
    const d = deps(() => Promise.reject({ code: 'ERR_GHOST_CARD_WRONG_CODE' }), ok());
    expect(await refillGhostCard(d, new Uint8Array(20))).toEqual({ ok: false, status: { kind: 'code-wrong', cardNumber: '' } });
  });
});

describe('the card module', () => {
  it('maps native failures and reads only parts of the right size', () => {
    expect(cardFailure({ code: 'ERR_NFC_CANCELLED' })).toBeInstanceOf(CardCancelled);
    expect(cardFailure({ code: 'ERR_GHOST_CARD_FAILED', message: 'The card refused a command (not a Ghost card).' })).toMatchObject({
      problem: 'refused',
      detail: 'not a Ghost card',
    });
    expect(cardFailure({ code: 'ERR_GHOST_CARD_NO_CHECKS' })).toMatchObject({ problem: 'no-checks' });
    expect(readTap({ kind: 'ntag' })).toEqual({ kind: 'ntag' });
    expect(() => readTap({ kind: 'ghost', identify: hex(28) })).toThrow();
    expect(() => readTap({ kind: 'ghost', identify: identify(0), make: hex(465) })).toThrow();
    expect(() => readTap({ kind: 'other' })).toThrow();
  });

  it('groups an open code in eights', () => {
    expect(openCodeGroups('abcdefgh ijklmnop-qrstuvwx yz234567')).toBe('ABCDEFGH IJKLMNOP QRSTUVWX YZ234567');
  });
});
