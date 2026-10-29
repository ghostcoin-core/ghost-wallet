// What the Send screen accepts before Face ID: a recipient pasted or typed as
// `0x` and 40 hex digits, and an amount in GHOST the account can pay with its
// fee. Amounts are worked out in wei with bigint arithmetic, never a float.
import { WEI_PER_GHOST, formatGhost } from '../home/balance-format';

/** The largest amount the native core takes (a u128 of wei). */
export const MAX_WEI = 2n ** 128n - 1n;

const ZERO_ADDRESS = `0x${'0'.repeat(40)}`;

export type AddressProblem = 'empty' | 'format' | 'zero' | 'own';

export type AddressCheck = { ok: true; address: string } | { ok: false; problem: AddressProblem };

/**
 * The recipient as `0x` and 40 lowercase hex digits. Spaces and line breaks a
 * paste carries around it are dropped; anything else wrong is refused, never
 * guessed at. Sending to this account itself or to the zero address is refused.
 */
export function checkAddress(text: string, own: string | null = null): AddressCheck {
  const trimmed = text.trim();
  if (trimmed === '') {
    return { ok: false, problem: 'empty' };
  }
  if (!/^0x[0-9a-fA-F]{40}$/.test(trimmed)) {
    return { ok: false, problem: 'format' };
  }
  const address = trimmed.toLowerCase();
  if (address === ZERO_ADDRESS) {
    return { ok: false, problem: 'zero' };
  }
  if (own && address === own.toLowerCase()) {
    return { ok: false, problem: 'own' };
  }
  return { ok: true, address };
}

export function addressMessage(problem: AddressProblem): string {
  switch (problem) {
    case 'empty':
      return 'Paste the address to send to.';
    case 'format':
      return 'A Ghost address is 0x and 40 letters and digits (0 to 9, a to f).';
    case 'zero':
      return 'No one can spend from this address. Check it.';
    case 'own':
      return 'This is your own address.';
  }
}

export type AmountProblem = 'empty' | 'format' | 'decimals' | 'zero' | 'too-large' | 'not-enough';

export type AmountCheck = { ok: true; wei: bigint } | { ok: false; problem: AmountProblem };

/**
 * The amount in wei. `balanceWei` and `feeWei` are null while not known (the
 * node is out of reach and nothing is cached): the amount is then checked
 * against what is known only. The fee is the most the send can pay.
 */
export function checkAmount(text: string, balanceWei: bigint | null, feeWei: bigint | null): AmountCheck {
  const trimmed = text.trim();
  if (trimmed === '') {
    return { ok: false, problem: 'empty' };
  }
  const match = /^(\d*)(?:[.,](\d*))?$/.exec(trimmed);
  if (!match || (match[1] === '' && (match[2] ?? '') === '')) {
    return { ok: false, problem: 'format' };
  }
  const fraction = match[2] ?? '';
  if (fraction.length > 18) {
    return { ok: false, problem: 'decimals' };
  }
  const wei = BigInt(match[1] === '' ? '0' : match[1]) * WEI_PER_GHOST + BigInt(fraction.padEnd(18, '0'));
  if (wei === 0n) {
    return { ok: false, problem: 'zero' };
  }
  if (wei > MAX_WEI) {
    return { ok: false, problem: 'too-large' };
  }
  if (balanceWei !== null && wei + (feeWei ?? 0n) > balanceWei) {
    return { ok: false, problem: 'not-enough' };
  }
  return { ok: true, wei };
}

export function amountMessage(problem: AmountProblem, balanceWei: bigint | null = null): string {
  switch (problem) {
    case 'empty':
      return 'Type the amount to send.';
    case 'format':
      return 'Type the amount in GHOST, for example 25.00.';
    case 'decimals':
      return 'GHOST has at most 18 decimals.';
    case 'zero':
      return 'Send more than nothing.';
    case 'too-large':
      return 'That is more GHOST than exists.';
    case 'not-enough':
      return balanceWei === null
        ? 'Not enough GHOST for the amount and its fee.'
        : `Not enough GHOST for the amount and its fee. You have ${formatGhost(balanceWei)} GHOST.`;
  }
}

/** The send's total: the amount and the most it can pay in fee. */
export function totalWei(amountWei: bigint, feeWei: bigint | null): bigint {
  return amountWei + (feeWei ?? 0n);
}
