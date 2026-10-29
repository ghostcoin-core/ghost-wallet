import { addressMessage, amountMessage, checkAddress, checkAmount, MAX_WEI, totalWei } from '../lib/send/validation';

const GHOST = 10n ** 18n;
const RECIPIENT = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';
const OWN = '0x00000000000000000000000000000000000000aa';

describe('the recipient address', () => {
  it('takes 0x and 40 hex digits, as lowercase', () => {
    expect(checkAddress(RECIPIENT)).toEqual({ ok: true, address: RECIPIENT });
    expect(checkAddress(RECIPIENT.toUpperCase().replace('0X', '0x'))).toEqual({ ok: true, address: RECIPIENT });
  });

  it('drops the spaces and line breaks a paste carries around it', () => {
    expect(checkAddress(`  ${RECIPIENT}\n`)).toEqual({ ok: true, address: RECIPIENT });
    expect(checkAddress(`\t${RECIPIENT} `)).toEqual({ ok: true, address: RECIPIENT });
  });

  it('says nothing is there yet when empty', () => {
    expect(checkAddress('')).toEqual({ ok: false, problem: 'empty' });
    expect(checkAddress('   \n')).toEqual({ ok: false, problem: 'empty' });
  });

  it('refuses anything that is not exactly an address, and never guesses', () => {
    const bad = [
      RECIPIENT.slice(2), // no 0x
      RECIPIENT.slice(0, -1), // 39 digits
      `${RECIPIENT}0`, // 41 digits
      `${RECIPIENT.slice(0, -1)}g`, // not hex
      `0X${RECIPIENT.slice(2)}`, // capital X
      `${RECIPIENT.slice(0, 20)} ${RECIPIENT.slice(20)}`, // a space inside
      `ghost:${RECIPIENT}`,
      `${RECIPIENT}?amount=1`,
      '0x',
    ];
    for (const text of bad) {
      expect(checkAddress(text)).toEqual({ ok: false, problem: 'format' });
    }
  });

  it('refuses the zero address and the account itself', () => {
    expect(checkAddress(`0x${'0'.repeat(40)}`)).toEqual({ ok: false, problem: 'zero' });
    expect(checkAddress(OWN, OWN)).toEqual({ ok: false, problem: 'own' });
    expect(checkAddress(OWN.toUpperCase().replace('0X', '0x'), OWN)).toEqual({ ok: false, problem: 'own' });
    expect(checkAddress(RECIPIENT, OWN).ok).toBe(true);
    expect(checkAddress(OWN, null).ok).toBe(true);
  });

  it('explains each problem in plain words', () => {
    expect(addressMessage('empty')).toBe('Paste the address to send to.');
    expect(addressMessage('format')).toContain('0x and 40');
    expect(addressMessage('own')).toBe('This is your own address.');
    expect(addressMessage('zero')).toContain('No one can spend');
  });
});

describe('the amount', () => {
  it('reads GHOST as wei, with a dot or a comma, never through a float', () => {
    expect(checkAmount('25', null, null)).toEqual({ ok: true, wei: 25n * GHOST });
    expect(checkAmount('25.00', null, null)).toEqual({ ok: true, wei: 25n * GHOST });
    expect(checkAmount('0,5', null, null)).toEqual({ ok: true, wei: GHOST / 2n });
    expect(checkAmount('.25', null, null)).toEqual({ ok: true, wei: GHOST / 4n });
    expect(checkAmount('3.', null, null)).toEqual({ ok: true, wei: 3n * GHOST });
    expect(checkAmount(' 1.5 ', null, null)).toEqual({ ok: true, wei: 1_500_000_000_000_000_000n });
    // 0.1 + 0.2 in floats is 0.30000000000000004: here it is exact.
    expect(checkAmount('0.3', null, null)).toEqual({ ok: true, wei: 300_000_000_000_000_000n });
    expect(checkAmount('0.000000000000000001', null, null)).toEqual({ ok: true, wei: 1n });
    expect(checkAmount('123456789.123456789123456789', null, null)).toEqual({
      ok: true,
      wei: 123_456_789_123_456_789_123_456_789n,
    });
  });

  it('says nothing is there yet when empty', () => {
    expect(checkAmount('', null, null)).toEqual({ ok: false, problem: 'empty' });
    expect(checkAmount('  ', null, null)).toEqual({ ok: false, problem: 'empty' });
  });

  it('refuses text that is not an amount', () => {
    for (const text of ['abc', '.', ',', '1.2.3', '1,000.50', '-1', '+1', '1e18', '0x10', '1 000', 'Infinity', '12 GHOST']) {
      expect(checkAmount(text, null, null)).toEqual({ ok: false, problem: 'format' });
    }
  });

  it('refuses more than 18 decimals rather than cutting them', () => {
    expect(checkAmount('1.0000000000000000001', null, null)).toEqual({ ok: false, problem: 'decimals' });
    expect(checkAmount('0.000000000000000000', null, null)).toEqual({ ok: false, problem: 'zero' });
  });

  it('refuses nothing', () => {
    expect(checkAmount('0', null, null)).toEqual({ ok: false, problem: 'zero' });
    expect(checkAmount('0.00', null, null)).toEqual({ ok: false, problem: 'zero' });
    expect(checkAmount('000', null, null)).toEqual({ ok: false, problem: 'zero' });
  });

  it('refuses more than the native core can carry', () => {
    const limit = MAX_WEI / GHOST;
    expect(checkAmount(limit.toString(), null, null).ok).toBe(true);
    expect(checkAmount((limit + 1n).toString(), null, null)).toEqual({ ok: false, problem: 'too-large' });
  });

  it('needs the balance to cover the amount and the most the fee can be', () => {
    const balance = 10n * GHOST;
    const fee = GHOST / 1000n;
    expect(checkAmount('9.999', balance, fee)).toEqual({ ok: true, wei: balance - fee });
    expect(checkAmount('9.9991', balance, fee)).toEqual({ ok: false, problem: 'not-enough' });
    expect(checkAmount('10', balance, fee)).toEqual({ ok: false, problem: 'not-enough' });
    expect(checkAmount('10', balance, null)).toEqual({ ok: true, wei: balance });
    expect(checkAmount('10.000000000000000001', balance, null)).toEqual({ ok: false, problem: 'not-enough' });
    expect(checkAmount('0.001', 0n, null)).toEqual({ ok: false, problem: 'not-enough' });
  });

  it('checks only what is known while the balance is not', () => {
    expect(checkAmount('1000000', null, GHOST)).toEqual({ ok: true, wei: 1_000_000n * GHOST });
  });

  it('explains each problem in plain words', () => {
    expect(amountMessage('not-enough', 1_284_500_000_000_000_000_000n)).toBe(
      'Not enough GHOST for the amount and its fee. You have 1,284.50 GHOST.',
    );
    expect(amountMessage('not-enough')).toBe('Not enough GHOST for the amount and its fee.');
    expect(amountMessage('decimals')).toContain('18 decimals');
    expect(amountMessage('zero')).toBe('Send more than nothing.');
    expect(amountMessage('format')).toContain('25.00');
  });

  it('totals the amount and the fee', () => {
    expect(totalWei(25n * GHOST, 2n * (GHOST / 1000n))).toBe(25_002_000_000_000_000_000n);
    expect(totalWei(25n * GHOST, null)).toBe(25n * GHOST);
  });
});
