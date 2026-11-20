/* eslint-disable @typescript-eslint/no-require-imports -- the jest.mock factory reaches the test's world lazily */
// A Ghost card as a vault (lib/ghost-card/vault.ts), against a simulated card
// (one coin at a time, as the applet) and a simulated chain and wallet: what
// the card holds after each Add and Take off, that the old coin's key is kept
// on this phone before the card is cleared, that nothing is lost when a hold
// is cut off, and that the background moves Summon the old coin before they
// pay the new one.
import type { CardKeyStore } from '../../modules/ghost-nfc/java-card';
import type { CheckResult, FillResult, OpenResult, RefillResult } from '../../lib/ghost-card/flows';
import {
  cardBalance,
  changeCard,
  moveChanges,
  takeProblem,
  type CardChange,
  type ChangeStore,
  type PaymentState,
  type VaultDeps,
} from '../../lib/ghost-card/vault';

const GHOST = 10n ** 18n;
const FEE = 10n ** 15n;
const MINIMUM = 10n ** 17n;
const CARD_ID = new Uint8Array(16).fill(0x11);

type Coin = { amount: bigint; paid: boolean; spent: boolean };

/** The world: one card, the chain's coins, the wallet, and what happened in order. */
class World {
  coins = new Map<number, Coin>();
  nextCoin = 1;
  card: { state: 'blank' | 'sealed' | 'opened'; fill: number; coin: number | null } = { state: 'blank', fill: 0, coin: null };
  wallet = 100n * GHOST;
  held: number | null = null;
  kept = new Map<string, number>();
  payments = new Map<string, { kind: 'summon' | 'vanish'; coin: number; state: PaymentState }>();
  saved: CardChange[] = [];
  log: string[] = [];
  network = true;
  /** The card is pulled away during the next remake. */
  pullNextRemake = false;
  /** The card is pulled away before the next clear. */
  pullNextRefill = false;
  /** The app is killed right after the card makes its next key. */
  killAfterNextMake = false;
  /** The app is killed right after the card's next Open. */
  killAfterNextOpen = false;
  /** The next Check tap reads nothing. */
  failNextCheck = false;
  /** Another card is held for the next Open. */
  swapCardBeforeOpen = false;

  marker(coin: number): Uint8Array {
    return new Uint8Array(32).fill(coin);
  }

  commitData(coin: number): Uint8Array {
    return new Uint8Array(430).fill(coin);
  }

  coinOf(bytes: Uint8Array): number {
    return bytes[0];
  }

  /** What the card holds as the chain shows it. */
  onCard(): bigint {
    const coin = this.card.coin === null ? null : this.coins.get(this.card.coin);
    return this.card.state === 'sealed' && coin?.paid && !coin.spent ? coin.amount : 0n;
  }

  open(only?: { cardId: Uint8Array; fill: number }): OpenResult {
    const { card } = this;
    this.log.push('open');
    if (this.swapCardBeforeOpen) {
      // Another card is tapped on the Open's sheet: it has another id.
      this.swapCardBeforeOpen = false;
      if (only) {
        return { ok: false, status: { kind: 'retry', message: 'This is not the card that was checked.' } };
      }
    }
    if (only && only.fill !== card.fill) {
      return { ok: false, status: { kind: 'retry', message: 'This is not the card that was checked.' } };
    }
    if (card.state === 'blank') {
      return {
        ok: false,
        status: { kind: 'blank', fill: card.fill, checksLeft: 900, cardNumber: 'CARD' },
        blank: { cardId: CARD_ID, fill: card.fill, cardNumber: 'CARD' },
      };
    }
    const coin = this.coins.get(card.coin!)!;
    if (card.state === 'opened' && coin.spent) {
      return {
        ok: false,
        status: { kind: 'opened', fill: card.fill, cardNumber: 'CARD', spent: true },
        reuse: { cardId: CARD_ID, fill: card.fill },
      };
    }
    if (card.state === 'opened' && !coin.paid) {
      // Opened, its commit data gone and no leaf on chain: the core cannot check the release.
      return { ok: false, status: { kind: 'not-on-chain', fill: card.fill, amountWei: coin.amount, cardNumber: 'CARD' } };
    }
    const was = card.state;
    card.state = 'opened';
    this.held = card.coin;
    if (this.killAfterNextOpen) {
      this.killAfterNextOpen = false;
      this.held = null;
      throw new Error('killed');
    }
    return {
      ok: true,
      amountWei: coin.amount,
      cardId: CARD_ID,
      fill: card.fill,
      cardNumber: 'CARD',
      ms: 3000,
      coin: {
        state: was === 'opened' ? 'opened' : 'sealed',
        commitment: this.marker(card.coin!),
        marker: this.marker(card.coin!),
        commitData: was === 'sealed' ? this.commitData(card.coin!) : null,
      },
    };
  }

  remake(fill: number, amount: bigint): FillResult {
    const { card } = this;
    this.log.push('remake');
    if (this.pullNextRemake) {
      this.pullNextRemake = false;
      // Cleared, then pulled away before Make.
      card.state = 'blank';
      card.coin = null;
      return { ok: false, status: { kind: 'retry', message: 'The card moved away.' } };
    }
    expect(card.fill).toBe(fill);
    expect(card.state === 'opened' || card.state === 'blank').toBe(true);
    const coin = this.nextCoin++;
    this.coins.set(coin, { amount, paid: false, spent: false });
    card.state = 'sealed';
    card.fill += 1;
    card.coin = coin;
    if (this.killAfterNextMake) {
      this.killAfterNextMake = false;
      throw new Error('killed');
    }
    return { ok: true, commitData: this.commitData(coin), amountWei: amount, fill: card.fill, cardNumber: 'CARD', checksLeft: 900, ms: 4000 };
  }

  refill(): RefillResult {
    this.log.push('refill');
    if (this.pullNextRefill) {
      this.pullNextRefill = false;
      return { ok: false, status: { kind: 'retry', message: 'The card moved away.' } };
    }
    this.card.state = 'blank';
    this.card.coin = null;
    return { ok: true, fill: this.card.fill, ms: 500 };
  }

  /** A Check tap, with the statement fields the vault reads. */
  checkTap(): CheckResult {
    this.log.push('check');
    if (this.failNextCheck) {
      this.failNextCheck = false;
      return { status: { kind: 'retry', message: 'The card could not be read.' }, statement: null, ms: null, commitData: null };
    }
    const result = this.check();
    const coin = this.card.coin === null ? null : this.coins.get(this.card.coin)!;
    return {
      ...result,
      statement: {
        ...result.statement!,
        state: this.card.state,
        amountWei: (coin?.amount ?? 0n).toString(),
      } as CheckResult['statement'],
    };
  }

  check(): CheckResult {
    const { card } = this;
    const coin = card.coin === null ? null : this.coins.get(card.coin)!;
    const statement = {
      cardId: CARD_ID.buffer,
      cardNumber: 'CARD',
      fill: card.fill,
      amountWei: (coin?.amount ?? 0n).toString(),
    } as unknown as CheckResult['statement'];
    if (card.state === 'blank' || !coin) {
      return { status: { kind: 'blank', fill: card.fill, checksLeft: 900, cardNumber: 'CARD' }, statement, ms: 1, commitData: null };
    }
    if (card.state === 'opened') {
      return { status: { kind: 'opened', fill: card.fill, cardNumber: 'CARD', spent: coin.spent }, statement, ms: 1, commitData: null };
    }
    const status = coin.paid
      ? ({ kind: 'sealed', fill: card.fill, amountWei: coin.amount, checksLeft: 900, cardNumber: 'CARD' } as const)
      : ({ kind: 'not-on-chain', fill: card.fill, amountWei: coin.amount, cardNumber: 'CARD' } as const);
    return { status, statement, ms: 1, commitData: this.commitData(card.coin!) };
  }

  keys(): CardKeyStore {
    return {
      keepCardKey: (tag) => {
        // As ios/CardKeyKeychain.swift takes it: the marker as 64 hex digits.
        expect(tag).toMatch(/^[0-9a-f]{64}$/);
        if (this.held === null) {
          throw new Error('no key held');
        }
        this.log.push('keep');
        this.kept.set(tag, this.held);
      },
      restoreCardKey: (tag) => {
        expect(tag).toMatch(/^[0-9a-f]{64}$/);
        const coin = this.kept.get(tag);
        if (coin === undefined) {
          return false;
        }
        this.held = coin;
        return true;
      },
      hasKeptCardKey: (tag) => this.kept.has(tag),
      forgetKeptCardKey: (tag) => {
        this.kept.delete(tag);
      },
    };
  }

  store(): ChangeStore {
    return {
      read: () => this.saved,
      write: async (changes) => {
        this.saved = changes;
      },
    };
  }

  deps(): VaultDeps {
    return {
      card: {
        core: {} as never,
        nfc: {} as never,
        chainId: 1n,
        coinOnChain: async (_commitment, marker) => {
          if (!this.network) {
            throw new Error('no node');
          }
          const coin = this.coins.get(this.coinOf(marker))!;
          return { status: coin.paid ? 'buried' : 'absent', spent: coin.spent, leaf: null };
        },
      },
      keys: this.keys(),
      changes: this.store(),
      payments: {
        lookUpHeldKey: async () => {
          const coin = this.coins.get(this.held!)!;
          return coin.spent ? 'spent' : coin.paid ? 'found' : 'not-found';
        },
        summonHeldKey: async () => {
          const id = `summon-${this.held}`;
          this.log.push(id);
          this.payments.set(id, { kind: 'summon', coin: this.held!, state: 'moving' });
          return id;
        },
        moveSummon: async (id) => {
          const p = this.payments.get(id)!;
          expect(this.held).toBe(p.coin);
          if (p.state === 'in-block') {
            // Only moving it on makes it settle: nothing else moves it.
            p.state = 'settled';
            return;
          }
          const coin = this.coins.get(p.coin)!;
          coin.spent = true;
          this.wallet += coin.amount - FEE;
          p.state = 'in-block';
        },
        paymentState: (id) => {
          const p = this.payments.get(id);
          return p?.state ?? 'missing';
        },
        startVanish: async (amount, commitData) => {
          const coin = this.coinOf(commitData);
          const id = `vanish-${coin}`;
          this.log.push(id);
          if (this.wallet < amount + FEE) {
            this.payments.set(id, { kind: 'vanish', coin, state: 'failed' });
            return id;
          }
          this.wallet -= amount + FEE;
          this.coins.get(coin)!.paid = true;
          this.payments.set(id, { kind: 'vanish', coin, state: 'in-block' });
          return id;
        },
        vanishSavedInto: (hex) => {
          const coin = parseInt(hex.slice(2, 4), 16);
          const p = this.payments.get(`vanish-${coin}`);
          return !!p && p.state !== 'failed';
        },
        forgetHeldKey: () => {
          this.held = null;
        },
      },
    };
  }

  /** A block: every payment in a block settles. */
  settle() {
    for (const p of this.payments.values()) {
      if (p.kind === 'vanish' && p.state === 'in-block') {
        p.state = 'settled';
      }
    }
  }

  /** Home's background moves until nothing more happens. */
  async finish() {
    for (let i = 0; i < 8; i++) {
      await moveChanges(this.deps());
      this.settle();
    }
  }
}

let world: World;

jest.mock('../../lib/ghost-card/flows', () => ({
  ...jest.requireActual('../../lib/ghost-card/flows'),
  openGhostCard: async (_deps: unknown, only?: { cardId: Uint8Array; fill: number }) => require('./vault.test').current().open(only),
  remakeGhostCard: async (_deps: unknown, target: { fill: number }, amount: bigint) =>
    require('./vault.test').current().remake(target.fill, amount),
  refillGhostCard: async () => require('./vault.test').current().refill(),
  checkGhostCard: async () => require('./vault.test').current().checkTap(),
}));
jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));

export function current(): World {
  return world;
}

beforeEach(() => {
  world = new World();
});

async function add(ghost: bigint) {
  return changeCard(world.deps(), { kind: 'add', amountWei: ghost * GHOST }, MINIMUM);
}

async function take(ghost: bigint | null) {
  return changeCard(world.deps(), { kind: 'take', amountWei: ghost === null ? null : ghost * GHOST }, MINIMUM);
}

it('adds up like a vault: 5, then 10, then 20 make 35; taking 3 leaves 32; taking all leaves it empty', async () => {
  expect(await add(5n)).toEqual({ ok: true, cardNumber: 'CARD', beforeWei: 0n, afterWei: 5n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(5n * GHOST);

  expect(await add(10n)).toMatchObject({ ok: true, beforeWei: 5n * GHOST, afterWei: 15n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(15n * GHOST);

  expect(await add(20n)).toMatchObject({ ok: true, beforeWei: 15n * GHOST, afterWei: 35n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(35n * GHOST);
  expect(cardBalance(world.deps(), world.check())).toEqual({ kind: 'holds', cardNumber: 'CARD', amountWei: 35n * GHOST, updating: false });

  const walletBefore = world.wallet;
  expect(await take(3n)).toMatchObject({ ok: true, beforeWei: 35n * GHOST, afterWei: 32n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(32n * GHOST);
  // 3 came home, less the Summon fee and the Vanish fee of what went back.
  expect(world.wallet).toBe(walletBefore + 3n * GHOST - 2n * FEE);

  expect(await take(null)).toMatchObject({ ok: true, beforeWei: 32n * GHOST, afterWei: 0n });
  await world.finish();
  expect(world.onCard()).toBe(0n);
  expect(cardBalance(world.deps(), world.check())).toEqual({ kind: 'empty', cardNumber: 'CARD' });
  // Every change finished, and no opened card's key is left on the phone.
  expect(world.saved).toEqual([]);
  expect(world.kept.size).toBe(0);
});

it('keeps the old key on this phone before the card is cleared, and Summons it before paying the new coin', async () => {
  await add(5n);
  await world.finish();
  world.log = [];
  await add(10n);
  expect(world.log).toEqual(['open', 'keep', 'remake']);
  await world.finish();
  expect(world.log.indexOf('summon-1')).toBeLessThan(world.log.indexOf('vanish-2'));
});

it('a change on top of one still going through counts it, and both finish', async () => {
  await add(5n);
  // The first Vanish is not paid yet: the card shows what it will hold.
  expect(cardBalance(world.deps(), world.check())).toMatchObject({ kind: 'holds', amountWei: 5n * GHOST, updating: true });
  await add(10n);
  expect(world.onCard()).toBe(0n);
  await world.finish();
  expect(world.onCard()).toBe(15n * GHOST);
  expect(world.saved).toEqual([]);
});

it('a hold cut off before the new key loses nothing, changes nothing, and the next hold carries on', async () => {
  await add(5n);
  await world.finish();
  world.pullNextRemake = true;
  const cut = await add(10n);
  expect(cut).toEqual({ ok: false, message: expect.stringMatching(/not changed/) });
  // The card is cleared but its coin is untouched and its key kept: it still shows 5.
  expect(world.kept.size).toBe(1);
  expect(cardBalance(world.deps(), world.check())).toMatchObject({ kind: 'holds', amountWei: 5n * GHOST });
  await world.finish();
  expect(world.coins.get(1)!.spent).toBe(false);

  expect(await add(10n)).toMatchObject({ ok: true, beforeWei: 5n * GHOST, afterWei: 15n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(15n * GHOST);
  expect(world.kept.size).toBe(0);
});

it('an empty card that was opened and emptied elsewhere is just filled', async () => {
  await add(5n);
  await world.finish();
  // Someone opened it and took its coin off on another phone.
  world.card.state = 'opened';
  world.coins.get(1)!.spent = true;
  expect(cardBalance(world.deps(), world.check())).toEqual({ kind: 'empty', cardNumber: 'CARD' });
  expect(await add(2n)).toMatchObject({ ok: true, beforeWei: 0n, afterWei: 2n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(2n * GHOST);
});

it('a card made but never paid (not by this phone) holds nothing', async () => {
  const coin = world.nextCoin++;
  world.coins.set(coin, { amount: 7n * GHOST, paid: false, spent: false });
  world.card = { state: 'sealed', fill: 1, coin };
  expect(cardBalance(world.deps(), world.check())).toEqual({ kind: 'empty', cardNumber: 'CARD' });
  expect(await add(1n)).toMatchObject({ ok: true, beforeWei: 0n, afterWei: 1n * GHOST });
});

it('with no network, nothing is changed', async () => {
  await add(5n);
  await world.finish();
  world.network = false;
  world.log = [];
  expect(await add(1n)).toEqual({ ok: false, message: expect.stringMatching(/Ghost network/) });
  expect(world.log).not.toContain('remake');
  expect(world.card.fill).toBe(1);
  // The card answers an Open again: with the network back, the change goes through.
  world.network = true;
  expect(await add(1n)).toMatchObject({ ok: true, beforeWei: 5n * GHOST, afterWei: 6n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(6n * GHOST);
});

it('refuses to take more than the card holds, or to leave less than a card can hold', async () => {
  await add(5n);
  await world.finish();
  expect(await take(6n)).toEqual({ ok: false, message: 'This card holds only 5 GHOST.' });
  expect(takeProblem(6n * GHOST, 5n * GHOST, MINIMUM, 0n, null)).toBe('The card holds 5 GHOST.');
  expect(takeProblem(5n * GHOST - MINIMUM / 2n, 5n * GHOST, MINIMUM, 0n, null)).toMatch(/Leave at least/);
  expect(takeProblem(5n * GHOST, 5n * GHOST, MINIMUM, 0n, { summon: FEE, vanish: FEE })).toBeNull();
  expect(takeProblem(FEE, 5n * GHOST, MINIMUM, 0n, { summon: FEE, vanish: FEE })).toMatch(/cover the fee/);
  expect(await take(null)).toMatchObject({ ok: true, afterWei: 0n });
  world.log = [];
  expect(await take(1n)).toEqual({ ok: false, message: 'This card is empty.' });
});

it('taking it all, then adding before the first change is done, brings the old coin home and fills the card anew', async () => {
  await add(35n);
  await world.finish();
  const walletBefore = world.wallet;
  expect(await take(null)).toMatchObject({ ok: true, afterWei: 0n });
  // At once, with nothing moved yet: the card is empty and is filled anew.
  expect(await add(5n)).toMatchObject({ ok: true, beforeWei: 0n, afterWei: 5n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(5n * GHOST);
  expect(world.wallet).toBe(walletBefore + 35n * GHOST - FEE - 5n * GHOST - FEE);
  expect(world.saved).toEqual([]);
  expect(world.kept.size).toBe(0);
});

it('taking it all on a card pulled away before it was cleared, then adding, does not count its coin twice', async () => {
  await add(35n);
  await world.finish();
  const walletBefore = world.wallet;
  world.pullNextRefill = true;
  expect(await take(null)).toMatchObject({ ok: true, afterWei: 0n });
  expect(world.card.state).toBe('opened');
  // The coin is already on its way home: the card holds nothing more.
  expect(await add(5n)).toMatchObject({ ok: true, beforeWei: 0n, afterWei: 5n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(5n * GHOST);
  expect(world.wallet).toBe(walletBefore + 35n * GHOST - FEE - 5n * GHOST - FEE);
  expect(world.saved).toEqual([]);
});

it('a card opened on another phone shows its balance with a warning, and its owner can still take it all', async () => {
  await add(5n);
  await world.finish();
  world.card.state = 'opened';
  const balance = cardBalance(world.deps(), {
    ...world.check(),
    statement: { ...world.check().statement!, marker: world.marker(1).buffer } as CheckResult['statement'],
  });
  expect(balance).toMatchObject({ kind: 'holds', amountWei: 5n * GHOST, warning: expect.stringMatching(/opened on another phone/) });
  expect(await take(null)).toMatchObject({ ok: true, beforeWei: 5n * GHOST, afterWei: 0n });
  await world.finish();
  expect(world.coins.get(1)!.spent).toBe(true);
});

it('a card made elsewhere and not yet paid keeps its key: a payment landing later comes home to the wallet', async () => {
  const coin = world.nextCoin++;
  world.coins.set(coin, { amount: 7n * GHOST, paid: false, spent: false });
  world.card = { state: 'sealed', fill: 1, coin };
  expect(await add(1n)).toMatchObject({ ok: true, beforeWei: 0n, afterWei: 1n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(1n * GHOST);
  expect(world.kept.size).toBe(1);
  // The other phone's payment lands late.
  world.coins.get(coin)!.paid = true;
  const walletBefore = world.wallet;
  jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 10 * 60 * 1000);
  await world.finish();
  jest.restoreAllMocks();
  expect(world.wallet).toBe(walletBefore + 7n * GHOST - FEE);
  expect(world.kept.size).toBe(0);
  expect(world.saved).toEqual([]);
});

it('an app killed right after the card made its new key loses nothing: the next hold finishes both changes', async () => {
  await add(5n);
  await world.finish();
  world.killAfterNextMake = true;
  await expect(add(10n)).rejects.toThrow('killed');
  // The card already holds its new key for 15, still unpaid; this phone shows what it will hold.
  expect(cardBalance(world.deps(), world.check())).toMatchObject({ kind: 'holds', amountWei: 15n * GHOST, updating: true });
  expect(await add(1n)).toMatchObject({ ok: true, beforeWei: 15n * GHOST, afterWei: 16n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(16n * GHOST);
  expect(world.saved).toEqual([]);
  expect(world.kept.size).toBe(0);
});

it('a recovery hold cut off right after its Open still loses nothing', async () => {
  await add(5n);
  await world.finish();
  world.killAfterNextMake = true;
  await expect(add(10n)).rejects.toThrow('killed');
  // The next hold reads the card first and saves its new coin, then is killed after the Open.
  world.killAfterNextOpen = true;
  await expect(add(1n)).rejects.toThrow('killed');
  expect(world.log).toContain('check');
  // The saved change finishes by itself: the old 5 comes home and 15 goes onto the card's coin.
  await world.finish();
  expect(world.coins.get(1)!.spent).toBe(true);
  expect(world.coins.get(2)!.paid).toBe(true);
  // The card is opened at that coin; the next hold carries on from 15.
  expect(await add(1n)).toMatchObject({ ok: true, beforeWei: 15n * GHOST, afterWei: 16n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(16n * GHOST);
  expect(world.saved).toEqual([]);
  expect(world.kept.size).toBe(0);
});

it('a coin nobody paid keeps its key past a week', async () => {
  const coin = world.nextCoin++;
  world.coins.set(coin, { amount: 7n * GHOST, paid: false, spent: false });
  world.card = { state: 'sealed', fill: 1, coin };
  await add(1n);
  await world.finish();
  jest.spyOn(Date, 'now').mockReturnValue(Date.now() + 30 * 24 * 60 * 60 * 1000);
  await world.finish();
  jest.restoreAllMocks();
  expect(world.kept.size).toBe(1);
  expect(world.saved).toHaveLength(1);
});

it('while a change is unfinished, a read that fails or another card on the Open sheet opens nothing', async () => {
  await add(5n);
  await world.finish();
  world.killAfterNextMake = true;
  await expect(add(10n)).rejects.toThrow('killed');

  world.log = [];
  world.failNextCheck = true;
  expect(await add(1n)).toMatchObject({ ok: false });
  expect(world.log).toEqual(['check']);
  expect(world.card.state).toBe('sealed');

  world.log = [];
  world.swapCardBeforeOpen = true;
  expect(await add(1n)).toMatchObject({ ok: false });
  expect(world.card.state).toBe('sealed');

  // The card was read and its new coin saved: everything still finishes.
  expect(await add(1n)).toMatchObject({ ok: true, beforeWei: 15n * GHOST, afterWei: 16n * GHOST });
  await world.finish();
  expect(world.onCard()).toBe(16n * GHOST);
  expect(world.saved).toEqual([]);
});
