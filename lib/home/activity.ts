// The home screen's activity list: what each payment row says, as in
// docs/mockups/home.html.
import { formatAge, formatSignedGhost, formatWhen, shortAddress } from './balance-format';

/** Where a payment stands, as the home screen tells it. */
export type ActivityState = 'pending' | 'done' | 'failed' | 'conflicted';

export type ActivityItem = {
  id: string;
  direction: 'sent' | 'received';
  /** The other account, `0x` and 40 hex digits; null when it is not known. */
  counterparty: string | null;
  /** The amount in wei, as decimal digits. */
  amountWei: string;
  state: ActivityState;
  /** When it was sent or first seen, in milliseconds since 1970. */
  at: number;
};

export type ActivityIcon = 'clock' | 'check' | 'cross' | 'warning';

/** One activity row, ready to draw. */
export type ActivityRow = {
  id: string;
  icon: ActivityIcon;
  title: string;
  detail: string;
  amount: string;
  /** Struck through: nothing moved. */
  struck: boolean;
};

/**
 * The state of a payment from the native core's step sequence
 * (`core/src/step_sequence.rs`, `Step`): every step before Settled is still
 * pending, Settled is done, Failed and Conflicted are their own states.
 */
export function activityStateFromStep(step: string): ActivityState {
  switch (step.toLowerCase()) {
    case 'settled':
      return 'done';
    case 'failed':
      return 'failed';
    case 'conflicted':
      return 'conflicted';
    default:
      return 'pending';
  }
}

function who(item: ActivityItem): string {
  return item.counterparty ? shortAddress(item.counterparty) : '';
}

function title(item: ActivityItem): string {
  const other = who(item);
  if (item.direction === 'received') {
    const verb = item.state === 'done' ? 'Received' : 'Receiving';
    return other ? `${verb} from ${other}` : verb;
  }
  // A send that went through reads "Sent"; one that did not reads "Send".
  const verb = item.state === 'failed' || item.state === 'conflicted' ? 'Send' : 'Sent';
  return other ? `${verb} to ${other}` : verb;
}

/** What a row says for `item`, at time `now`. */
export function describeActivity(item: ActivityItem, now: number): ActivityRow {
  const amount = formatSignedGhost(item.amountWei, item.direction);
  const base = { id: item.id, title: title(item), amount };
  switch (item.state) {
    case 'pending':
      return { ...base, icon: 'clock', detail: `Pending, ${formatAge(item.at, now)}`, struck: false };
    case 'done':
      return {
        ...base,
        icon: 'check',
        detail: `${item.direction === 'received' ? 'Received' : 'Sent'}, ${formatWhen(item.at, now)}`,
        struck: false,
      };
    case 'failed':
      return { ...base, icon: 'cross', detail: 'Failed, nothing spent', struck: true };
    case 'conflicted':
      return { ...base, icon: 'warning', detail: 'Conflicted, another send went first', struck: true };
  }
}

/** Pending payments first, then the newest. */
export function sortActivity(items: readonly ActivityItem[]): ActivityItem[] {
  return [...items].sort((a, b) => {
    const pendingA = a.state === 'pending' ? 0 : 1;
    const pendingB = b.state === 'pending' ? 0 : 1;
    return pendingA - pendingB || b.at - a.at;
  });
}

const STATES: readonly ActivityState[] = ['pending', 'done', 'failed', 'conflicted'];

/** An activity item read back from the cache, or null if it is malformed. */
export function parseActivityItem(raw: unknown): ActivityItem | null {
  if (typeof raw !== 'object' || raw === null) {
    return null;
  }
  const item = raw as Record<string, unknown>;
  const valid =
    typeof item.id === 'string' &&
    (item.direction === 'sent' || item.direction === 'received') &&
    (item.counterparty === null || (typeof item.counterparty === 'string' && /^0x[0-9a-f]{40}$/i.test(item.counterparty))) &&
    typeof item.amountWei === 'string' &&
    /^[0-9]+$/.test(item.amountWei) &&
    STATES.includes(item.state as ActivityState) &&
    typeof item.at === 'number' &&
    Number.isFinite(item.at);
  if (!valid) {
    return null;
  }
  return {
    id: item.id as string,
    direction: item.direction as ActivityItem['direction'],
    counterparty: item.counterparty as string | null,
    amountWei: item.amountWei as string,
    state: item.state as ActivityState,
    at: item.at as number,
  };
}
