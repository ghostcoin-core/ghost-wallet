import {
  activityStateFromStep,
  describeActivity,
  parseActivityItem,
  sortActivity,
  type ActivityItem,
} from '../../lib/home/activity';

const GHOST = 10n ** 18n;
const NOW = new Date(2026, 9, 28, 14, 30).getTime();

function item(change: Partial<ActivityItem>): ActivityItem {
  return {
    id: 'a',
    direction: 'sent',
    counterparty: '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd',
    amountWei: (25n * GHOST).toString(),
    state: 'pending',
    at: NOW - 2_000,
    ...change,
  };
}

describe('activity rows, as in the home mockup', () => {
  it('shows a pending send with a clock and its age', () => {
    expect(describeActivity(item({}), NOW)).toEqual({
      id: 'a',
      icon: 'clock',
      title: 'Sent to 0xe5fb…55fd',
      detail: 'Pending, just now',
      amount: '−25.00',
      struck: false,
    });
  });

  it('shows a received payment with a check and when it came', () => {
    const row = describeActivity(
      item({
        direction: 'received',
        counterparty: '0x3a1c' + '0'.repeat(32) + '9b02',
        amountWei: (40n * GHOST).toString(),
        state: 'done',
        at: new Date(2026, 9, 28, 9, 12).getTime(),
      }),
      NOW,
    );
    expect(row).toMatchObject({
      icon: 'check',
      title: 'Received from 0x3a1c…9b02',
      detail: 'Received, today 9:12',
      amount: '+40.00',
      struck: false,
    });
  });

  it('shows a failed send struck through: nothing was spent', () => {
    const row = describeActivity(item({ state: 'failed', amountWei: (10n * GHOST).toString() }), NOW);
    expect(row).toMatchObject({
      icon: 'cross',
      title: 'Send to 0xe5fb…55fd',
      detail: 'Failed, nothing spent',
      amount: '−10.00',
      struck: true,
    });
  });

  it('shows a conflicted send struck through with a warning', () => {
    const row = describeActivity(item({ state: 'conflicted', amountWei: ((42n * GHOST) / 10n).toString() }), NOW);
    expect(row).toMatchObject({
      icon: 'warning',
      title: 'Send to 0xe5fb…55fd',
      detail: 'Conflicted, another send went first',
      amount: '−4.20',
      struck: true,
    });
  });

  it('shows a settled send as sent, not struck', () => {
    const row = describeActivity(item({ state: 'done', at: new Date(2026, 9, 27, 8, 0).getTime() }), NOW);
    expect(row).toMatchObject({ icon: 'check', title: 'Sent to 0xe5fb…55fd', detail: 'Sent, yesterday 8:00', struck: false });
  });

  it('names no sender it does not know', () => {
    const row = describeActivity(item({ direction: 'received', counterparty: null, state: 'done' }), NOW);
    expect(row.title).toBe('Received');
    expect(describeActivity(item({ direction: 'received', counterparty: null }), NOW).title).toBe('Receiving');
  });

  it('gives a pending payment its age', () => {
    expect(describeActivity(item({ at: NOW - 5 * 60_000 }), NOW).detail).toBe('Pending, 5 minutes ago');
  });
});

describe('activityStateFromStep', () => {
  it('maps the core payment steps to what home shows', () => {
    for (const step of ['Prepared', 'BackedUp', 'Signed', 'Sent', 'Included']) {
      expect(activityStateFromStep(step)).toBe('pending');
    }
    expect(activityStateFromStep('Settled')).toBe('done');
    expect(activityStateFromStep('Failed')).toBe('failed');
    expect(activityStateFromStep('Conflicted')).toBe('conflicted');
    expect(activityStateFromStep('conflicted')).toBe('conflicted');
  });
});

describe('sortActivity', () => {
  it('puts pending payments first, then the newest', () => {
    const items = [
      item({ id: 'old-done', state: 'done', at: 1 }),
      item({ id: 'new-failed', state: 'failed', at: 30 }),
      item({ id: 'pending', state: 'pending', at: 5 }),
      item({ id: 'mid-conflicted', state: 'conflicted', at: 20 }),
    ];
    expect(sortActivity(items).map((i) => i.id)).toEqual(['pending', 'new-failed', 'mid-conflicted', 'old-done']);
    expect(items[0].id).toBe('old-done');
  });
});

describe('parseActivityItem', () => {
  it('reads back a cached item', () => {
    const cached = item({ state: 'conflicted' });
    expect(parseActivityItem(JSON.parse(JSON.stringify(cached)))).toEqual(cached);
  });

  it('drops malformed items', () => {
    expect(parseActivityItem(null)).toBeNull();
    expect(parseActivityItem({ ...item({}), state: 'lost' })).toBeNull();
    expect(parseActivityItem({ ...item({}), amountWei: '-5' })).toBeNull();
    expect(parseActivityItem({ ...item({}), counterparty: '0x12' })).toBeNull();
    expect(parseActivityItem({ ...item({}), direction: 'sideways' })).toBeNull();
  });
});
