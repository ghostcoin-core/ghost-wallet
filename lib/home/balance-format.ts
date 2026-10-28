// How amounts, addresses and ages read on the home screen.
//
// Balances arrive from the native core as a decimal number of wei (18
// decimals). They are formatted with bigint arithmetic, never through a float,
// and cut rather than rounded so a balance never reads higher than it is.

export const WEI_PER_GHOST = 10n ** 18n;

/** The minus sign amounts use (U+2212), as in the mockups. */
export const MINUS = '−';

const DECIMALS = 18;

/** A wei amount from the core (decimal digits) or a node (`0x` hex). */
export function parseWei(value: string | bigint): bigint {
  if (typeof value === 'bigint') {
    return value;
  }
  const text = value.trim();
  if (/^[0-9]+$/.test(text) || /^0x[0-9a-f]+$/i.test(text)) {
    return BigInt(text);
  }
  throw new Error('not an amount in wei');
}

function groupThousands(digits: string): string {
  return digits.replace(/\B(?=(\d{3})+(?!\d))/g, ',');
}

export type GhostFormat = {
  /** Decimals always shown (default 2). */
  minDecimals?: number;
  /** Decimals shown at most (default 6); the rest are cut, not rounded. */
  maxDecimals?: number;
};

/**
 * A wei amount in GHOST, thousands grouped: `1,284.50`. A non-zero amount too
 * small to show reads `<0.000001` rather than `0.00`.
 */
export function formatGhost(wei: string | bigint, format: GhostFormat = {}): string {
  const minDecimals = format.minDecimals ?? 2;
  const maxDecimals = Math.max(minDecimals, format.maxDecimals ?? 6);
  const value = parseWei(wei);
  const negative = value < 0n;
  const abs = negative ? -value : value;
  const whole = abs / WEI_PER_GHOST;
  const fraction = abs % WEI_PER_GHOST;

  const shown = fraction.toString().padStart(DECIMALS, '0').slice(0, maxDecimals).replace(/0+$/, '');
  if (whole === 0n && fraction > 0n && shown === '') {
    return `${negative ? MINUS : ''}<0.${'0'.repeat(maxDecimals - 1)}1`;
  }
  const decimals = shown.padEnd(minDecimals, '0');
  const sign = negative ? MINUS : '';
  return `${sign}${groupThousands(whole.toString())}${decimals ? `.${decimals}` : ''}`;
}

/** An activity amount with its direction: `+40.00` in, `−25.00` out. */
export function formatSignedGhost(wei: string | bigint, direction: 'sent' | 'received'): string {
  return `${direction === 'sent' ? MINUS : '+'}${formatGhost(wei)}`;
}

/** `0xe5fb…55fd`: the first and last four hex digits of an address. */
export function shortAddress(address: string): string {
  const hex = address.toLowerCase();
  if (!/^0x[0-9a-f]{40}$/.test(hex)) {
    return hex;
  }
  return `${hex.slice(0, 6)}…${hex.slice(-4)}`;
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

function plural(count: number, unit: string): string {
  return `${count} ${unit}${count === 1 ? '' : 's'} ago`;
}

/** How long ago `then` was: `just now`, `5 minutes ago`, `2 days ago`. */
export function formatAge(then: number, now: number): string {
  const age = Math.max(0, now - then);
  if (age < 45_000) {
    return 'just now';
  }
  if (age < HOUR) {
    return plural(Math.max(1, Math.round(age / MINUTE)), 'minute');
  }
  if (age < DAY) {
    return plural(Math.floor(age / HOUR), 'hour');
  }
  return plural(Math.floor(age / DAY), 'day');
}

const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

function startOfDay(time: number): number {
  const date = new Date(time);
  return new Date(date.getFullYear(), date.getMonth(), date.getDate()).getTime();
}

/** When something happened, in local time: `today 9:12`, `yesterday 18:05`, `26 Oct 9:12`. */
export function formatWhen(then: number, now: number): string {
  const date = new Date(then);
  const clock = `${date.getHours()}:${String(date.getMinutes()).padStart(2, '0')}`;
  const days = Math.round((startOfDay(now) - startOfDay(then)) / DAY);
  if (days === 0) {
    return `today ${clock}`;
  }
  if (days === 1) {
    return `yesterday ${clock}`;
  }
  return `${date.getDate()} ${MONTHS[date.getMonth()]} ${clock}`;
}
