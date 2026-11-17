import { createHash } from 'crypto';

import { act, fireEvent, render, screen, waitFor } from '@testing-library/react-native';

import CardProbeScreen from '../app/card-probe';
import {
  command,
  describeProbe,
  estimate,
  fromHex,
  runProbe,
  selectProbe,
  toHex,
  type ProbeReport,
} from '../modules/ghost-nfc/card-probe';

// A stand-in for the probe applet: it answers each command as the applet does
// and moves a fake clock by how long the card took over contact.
type FakeOptions = {
  /** The longest answer the phone takes; a longer one makes the tap fail. */
  maxAnswer?: number;
  /** Stop answering from this instruction on. */
  dieAt?: number;
  /** Answer the seal with a wrong tag. */
  badSeal?: boolean;
};

const SHA3 = '44095cad84b63d5b6d63521087c0db05c3f6007d31843085f9511715f0582727';
const SEAL = 'aa10fb34fd934a6d3c37926b1fbc6679' + '89fa0a032d12a347bf8a35f89410006c';

function parse(apdu: Uint8Array): { ins: number; p1p2: number; data: Uint8Array; le: number } {
  const ins = apdu[1];
  const p1p2 = (apdu[2] << 8) | apdu[3];
  if (apdu.length === 4) {
    return { ins, p1p2, data: new Uint8Array(0), le: 0 };
  }
  if (apdu[4] === 0 && apdu.length > 5) {
    if (apdu.length === 7) {
      return { ins, p1p2, data: new Uint8Array(0), le: (apdu[5] << 8) | apdu[6] };
    }
    const lc = (apdu[5] << 8) | apdu[6];
    const data = apdu.slice(7, 7 + lc);
    const rest = apdu.slice(7 + lc);
    return { ins, p1p2, data, le: rest.length === 2 ? (rest[0] << 8) | rest[1] : 0 };
  }
  if (apdu.length === 5) {
    return { ins, p1p2, data: new Uint8Array(0), le: apdu[4] === 0 ? 256 : apdu[4] };
  }
  const lc = apdu[4];
  const data = apdu.slice(5, 5 + lc);
  const rest = apdu.slice(5 + lc);
  return { ins, p1p2, data, le: rest.length === 1 ? (rest[0] === 0 ? 256 : rest[0]) : 0 };
}

function ok(...parts: Uint8Array[]): Uint8Array {
  const total = parts.reduce((n, p) => n + p.length, 0);
  const out = new Uint8Array(total + 2);
  let o = 0;
  for (const p of parts) {
    out.set(p, o);
    o += p.length;
  }
  out[total] = 0x90;
  out[total + 1] = 0x00;
  return out;
}

function fakeCard(options: FakeOptions = {}) {
  let clock = 0;
  const maxAnswer = options.maxAnswer ?? 256;
  const now = () => clock;
  const tag = {
    transceive: async (apdu: Uint8Array): Promise<Uint8Array> => {
      const { ins, p1p2, data } = parse(apdu);
      clock += 10;
      if (apdu[0] === 0x00 && ins === 0xa4) {
        return ok();
      }
      if (options.dieAt !== undefined && ins === options.dieAt) {
        throw new Error('tag lost');
      }
      switch (ins) {
        case 0x00:
          return ok();
        case 0x01: {
          const flags = Uint8Array.from([1, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 0]);
          const mem = fromHex('000267400000' + '07e6' + '000007e0');
          return ok(flags, mem);
        }
        case 0x10:
          clock += p1p2 * 2.4;
          return ok();
        case 0x20:
          clock += p1p2 * 1443;
          return ok();
        case 0x24:
          clock += p1p2 * 428;
          return ok();
        case 0x25:
          return ok(fromHex(SHA3));
        case 0x32: {
          clock += p1p2 * 600;
          const answer = fromHex(SEAL);
          if (options.badSeal) {
            answer[0] ^= 1;
          }
          return ok(answer);
        }
        case 0x40:
          clock += p1p2 * 1590;
          return ok(fromHex('00000246'));
        case 0x50: {
          const want = Math.max(34, p1p2);
          if (want > maxAnswer) {
            throw new Error('answer too long for this reader');
          }
          clock += data.length * 0.3 + want * 0.2;
          const head = new Uint8Array(createHash('sha256').update(data).digest());
          const answer = new Uint8Array(want).fill(0x5a);
          answer.set(head, 0);
          answer[32] = (data.length >> 8) & 0xff;
          answer[33] = data.length & 0xff;
          return ok(answer);
        }
        default:
          return Uint8Array.of(0x6d, 0x00);
      }
    },
  };
  return { tag, now };
}

describe('probe command framing', () => {
  it('uses the short form when the data and answer fit', () => {
    expect(toHex(command(0x24, 5))).toBe('80240005');
    expect(toHex(command(0x40, 1, undefined, 4))).toBe('8040000104');
    expect(toHex(command(0x50, 256, new Uint8Array(2).fill(0xcd), 256))).toBe('8050010002cdcd00');
  });

  it('uses the extended form for long data or a long answer', () => {
    const big = command(0x50, 34, new Uint8Array(1000), 34);
    expect(toHex(big.slice(0, 7))).toBe('80500022' + '0003e8');
    expect(big.length).toBe(7 + 1000 + 2);
    expect(toHex(big.slice(-2))).toBe('0022');
    expect(toHex(command(0x50, 257, new Uint8Array(16), 257).slice(-2))).toBe('0101');
  });

  it('selects the probe by its AID', () => {
    expect(toHex(selectProbe())).toBe('00a404000aa00000084750524f420100');
  });
});

describe('the probe run', () => {
  it('times each step and checks every answer', async () => {
    const card = fakeCard();
    const report = await runProbe(card.tag, card.now);

    expect(report.problems).toEqual([]);
    expect(report.noopMs).toBe(10);
    expect(report.sha256Ms).toBeCloseTo(2.4);
    expect(report.keccakFastMs).toBeCloseTo(428);
    expect(report.keccakPlainMs).toBeCloseTo(1443);
    expect(report.sha3Matches).toBe(true);
    expect(report.sealMs).toBeCloseTo(600);
    expect(report.sealMatches).toBe(true);
    expect(report.lmsSignMs).toBeCloseTo(1590);
    expect(report.lmsHashes).toBe(582);
    expect(report.extendedIn.ok).toBe(true);
    expect(report.info).toContain('SHA3-256: no');
    expect(report.info).toContain('free persistent: 157504 bytes');
  });

  it('says which long answers got through', async () => {
    const card = fakeCard({ maxAnswer: 256 });
    const report = await runProbe(card.tag, card.now);

    expect(report.longAnswers.map((a) => [a.asked, a.ok])).toEqual([
      [256, true],
      [257, false],
      [1000, false],
    ]);
    const full = fakeCard({ maxAnswer: 65536 });
    const all = await runProbe(full.tag, full.now);
    expect(all.longAnswers.every((a) => a.ok && a.got === a.asked)).toBe(true);
  });

  it('adds up Make, Check and Open as the measurements doc does', async () => {
    const card = fakeCard();
    const e = estimate(await runProbe(card.tag, card.now));

    expect(e.makeAsSpecifiedMs).toBeCloseTo(14 * 428 + 600 + 1590 + 200);
    expect(e.makeRecommendedMs).toBeCloseTo(10 * 428 + 600 + 200);
    expect(e.makePrecomputedMs).toBeCloseTo(428 + 600 + 1590 + 200);
    expect(e.openMs).toBeCloseTo(2 * 428 + 100);
    expect(e.checkMs).toBeGreaterThan(1590);
  });

  it('stops and says where when the card stops answering', async () => {
    const card = fakeCard({ dieAt: 0x24 });
    const report = await runProbe(card.tag, card.now);

    expect(report.problems).toEqual(['Keccak (fast): the card stopped answering']);
    expect(Number.isNaN(report.lmsSignMs)).toBe(true);
    expect(report.longAnswers).toEqual([]);
    expect(describeProbe(report)).not.toContain('estimates over NFC');
  });

  it('flags a wrong seal', async () => {
    const card = fakeCard({ badSeal: true });
    const report = await runProbe(card.tag, card.now);

    expect(report.sealMatches).toBe(false);
    expect(report.problems).toContain("seal: the card's ciphertext or tag is wrong");
  });

  it('prints the timings, the long answers and the budgets', async () => {
    const card = fakeCard();
    const text = describeProbe(await runProbe(card.tag, card.now));

    expect(text).toContain('Keccak-f[1600], fast: 428 ms per permutation (SHA3-256 right)');
    expect(text).toContain('note seal: 600 ms (tag right)');
    expect(text).toContain('answer of 257 bytes: no');
    expect(text).toContain('Make, as specified: 8.38 s (pass)');
    expect(text).toContain('Make, recommended: 5.08 s (pass)');
    expect(text).toContain('Open: 956 ms (pass)');
  });
});

// The reader runs only on the phone; the screen gets this stand-in.
const mockProbe = jest.fn();
jest.mock('../modules/ghost-nfc/card-probe', () => {
  const actual = jest.requireActual('../modules/ghost-nfc/card-probe');
  return { ...actual, probeCardOverNfc: (progress: (step: string) => void) => mockProbe(progress) };
});

describe('Card probe screen', () => {
  it('runs the probe and shows the timings', async () => {
    const card = fakeCard();
    const report: ProbeReport = await runProbe(card.tag, card.now);
    mockProbe.mockImplementation(async () => report);

    render(<CardProbeScreen />);
    expect(screen.getByRole('header', { name: 'Card probe' })).toBeOnTheScreen();
    expect(screen.getByTestId('card-probe-result')).toHaveTextContent('No run yet');

    await act(async () => {
      fireEvent.press(screen.getByTestId('card-probe-run'));
    });

    await waitFor(() =>
      expect(screen.getByTestId('card-probe-result')).toHaveTextContent('Keccak-f[1600], fast: 428 ms', { exact: false }),
    );
    expect(screen.getByTestId('card-probe-runs')).toHaveTextContent('run 1: Keccak 428 ms, every step ran');
  });

  it('shows an error run', async () => {
    mockProbe.mockImplementation(async () => {
      throw new Error('This iPhone cannot read cards.');
    });

    render(<CardProbeScreen />);
    await act(async () => {
      fireEvent.press(screen.getByTestId('card-probe-run'));
    });

    await waitFor(() => expect(screen.getByTestId('card-probe-result')).toHaveTextContent('error: This iPhone cannot read cards.'));
  });
});
