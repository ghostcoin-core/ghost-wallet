// Activity's card rows (lib/ghost-card/card-activity.ts): one row for each
// change of a card's balance, in place of its Summon and Vanish.
import { noteChange, withCardActivity, type CardActivityEntry, type CardActivityStore } from '../../lib/ghost-card/card-activity';
import { describeActivity, parseActivityItem, type ActivityItem } from '../../lib/home/activity';

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));

const GHOST = 10n ** 18n;

function memory(): CardActivityStore & { rows: CardActivityEntry[] } {
  const store = {
    rows: [] as CardActivityEntry[],
    read: () => store.rows,
    write: async (entries: CardActivityEntry[]) => {
      store.rows = entries;
    },
  };
  return store;
}

function payment(id: string, kind: 'summon' | 'vanish', amount: bigint): ActivityItem {
  return {
    id,
    direction: kind === 'vanish' ? 'sent' : 'received',
    counterparty: null,
    amountWei: amount.toString(),
    state: 'done',
    at: 1,
    kind,
  };
}

it('shows a card holding 1 that has 2 added as "Added to card −2", not a Summon of 1 and a Vanish of 3', async () => {
  const store = memory();
  const change = { id: 'c1', beforeWei: (1n * GHOST).toString(), afterWei: (3n * GHOST).toString(), at: 5, summonId: 's1', vanishId: null };
  await noteChange(store, change, false);
  await noteChange(store, { ...change, vanishId: 'v1' }, true);
  const items = withCardActivity(
    [payment('s1', 'summon', 1n * GHOST), payment('v1', 'vanish', 3n * GHOST), payment('other', 'vanish', GHOST)],
    store.rows,
  );
  expect(items.map((i) => i.id)).toEqual(['other', 'card-c1']);
  const row = describeActivity(items[1], 10);
  expect(row.title).toBe('Added to card');
  expect(row.amount).toContain('2');
  expect(row.amount).not.toContain('3');
});

it('says taking off as received, and keeps a payment hidden once listed even after it is made again', async () => {
  const store = memory();
  const change = { id: 'c2', beforeWei: (5n * GHOST).toString(), afterWei: (2n * GHOST).toString(), at: 5, summonId: 's1', vanishId: null };
  await noteChange(store, change, false);
  await noteChange(store, { ...change, summonId: null }, false);
  await noteChange(store, { ...change, summonId: 's2' }, false);
  expect(store.rows).toEqual([
    { id: 'c2', kind: 'take', amountWei: (3n * GHOST).toString(), at: 5, paymentIds: ['s1', 's2'], done: false },
  ]);
  const [item] = withCardActivity([], store.rows);
  expect(describeActivity(item, 10).title).toBe('Taking off card');
  expect(item.direction).toBe('received');
  // A cached card row reads back.
  expect(parseActivityItem(item)).toEqual(item);
});
