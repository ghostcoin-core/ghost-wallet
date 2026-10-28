import {
  MINUS,
  formatAge,
  formatGhost,
  formatSignedGhost,
  formatWhen,
  parseWei,
  shortAddress,
} from '../../lib/home/balance-format';

const GHOST = 10n ** 18n;

describe('formatGhost', () => {
  it('shows whole GHOST with two decimals and grouped thousands', () => {
    expect(formatGhost(0n)).toBe('0.00');
    expect(formatGhost(GHOST)).toBe('1.00');
    expect(formatGhost(1284n * GHOST + GHOST / 2n)).toBe('1,284.50');
    expect(formatGhost(1_234_567n * GHOST)).toBe('1,234,567.00');
  });

  it('reads the decimal wei the core gives and the hex a node gives', () => {
    expect(formatGhost('1000000000000000000')).toBe('1.00');
    expect(formatGhost('0xde0b6b3a7640000')).toBe('1.00');
    expect(parseWei(' 42 ')).toBe(42n);
  });

  it('refuses text that is not an amount', () => {
    expect(() => parseWei('1.5')).toThrow('not an amount');
    expect(() => parseWei('-1')).toThrow('not an amount');
    expect(() => parseWei('')).toThrow('not an amount');
  });

  it('shows up to six decimals and cuts the rest instead of rounding up', () => {
    expect(formatGhost(1_234_567_890_000_000_000n)).toBe('1.234567');
    expect(formatGhost(1_999_999_999_999_999_999n)).toBe('1.999999');
    expect(formatGhost(1_250_000_000_000_000_000n)).toBe('1.25');
    expect(formatGhost(1_200_000_000_000_000_000n)).toBe('1.20');
  });

  it('never shows dust as zero', () => {
    expect(formatGhost(1n)).toBe('<0.000001');
    expect(formatGhost(999_999_999_999n)).toBe('<0.000001');
    expect(formatGhost(1_000_000_000_000n)).toBe('0.000001');
  });

  it('keeps every digit of balances beyond what a float holds', () => {
    const big = 123_456_789_012_345_678_901_234_567n;
    expect(formatGhost(big)).toBe('123,456,789.012345');
  });

  it('takes other decimal limits', () => {
    expect(formatGhost(1_234_567_890_000_000_000n, { maxDecimals: 2 })).toBe('1.23');
    expect(formatGhost(GHOST, { minDecimals: 0 })).toBe('1');
  });
});

describe('formatSignedGhost', () => {
  it('marks money in with + and money out with the minus sign', () => {
    expect(formatSignedGhost(40n * GHOST, 'received')).toBe('+40.00');
    expect(formatSignedGhost(25n * GHOST, 'sent')).toBe(`${MINUS}25.00`);
    expect(MINUS).toBe('−');
  });
});

describe('shortAddress', () => {
  it('keeps the first and last four hex digits', () => {
    expect(shortAddress('0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd')).toBe('0xe5fb…55fd');
    expect(shortAddress('0xE5FBE4D8256744EC6FD55F2CE5BDFAE7CBF355FD')).toBe('0xe5fb…55fd');
  });

  it('leaves something that is not an address as it is', () => {
    expect(shortAddress('0x1234')).toBe('0x1234');
  });
});

describe('formatAge', () => {
  const now = 1_800_000_000_000;

  it('says how long ago the balance was checked', () => {
    expect(formatAge(now, now)).toBe('just now');
    expect(formatAge(now - 44_000, now)).toBe('just now');
    expect(formatAge(now - 60_000, now)).toBe('1 minute ago');
    expect(formatAge(now - 5 * 60_000, now)).toBe('5 minutes ago');
    expect(formatAge(now - 60 * 60_000, now)).toBe('1 hour ago');
    expect(formatAge(now - 3 * 60 * 60_000, now)).toBe('3 hours ago');
    expect(formatAge(now - 2 * 24 * 60 * 60_000, now)).toBe('2 days ago');
  });

  it('treats a time ahead of the clock as just now', () => {
    expect(formatAge(now + 60_000, now)).toBe('just now');
  });
});

describe('formatWhen', () => {
  const now = new Date(2026, 9, 28, 14, 30).getTime();

  it('names today and yesterday and dates anything older', () => {
    expect(formatWhen(new Date(2026, 9, 28, 9, 12).getTime(), now)).toBe('today 9:12');
    expect(formatWhen(new Date(2026, 9, 27, 18, 5).getTime(), now)).toBe('yesterday 18:05');
    expect(formatWhen(new Date(2026, 9, 26, 9, 2).getTime(), now)).toBe('26 Oct 9:02');
  });
});
