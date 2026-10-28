// An amount typed in GHOST, as wei.
import { WEI_PER_GHOST } from '../home/balance-format';

/** `1.5` → 1.5 GHOST in wei; null for anything that is not a positive amount with at most 18 decimals. */
export function parseGhostAmount(text: string): bigint | null {
  const match = /^\s*(\d*)(?:[.,](\d{0,18}))?\s*$/.exec(text);
  if (!match || (match[1] === '' && (match[2] ?? '') === '')) {
    return null;
  }
  const whole = BigInt(match[1] === '' ? '0' : match[1]);
  const fraction = BigInt((match[2] ?? '').padEnd(18, '0'));
  const wei = whole * WEI_PER_GHOST + fraction;
  return wei > 0n ? wei : null;
}
