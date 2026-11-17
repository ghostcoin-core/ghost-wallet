// Which screens can be open. The root layout gives each group to a
// Stack.Protected guard; a screen whose guard is false is closed and the
// router falls back to the first open screen in the layout's order:
// onboarding, then the lock, then the wallet.

export type AccountState = {
  /** Account words are saved in this device's Keychain. */
  hasAccount: boolean;
  /** The person passed Face ID or the passcode since the app opened. */
  unlocked: boolean;
};

export type RouteGroup = 'onboarding' | 'lock' | 'wallet' | 'developer';

export const ROUTE_GROUPS = {
  index: 'onboarding',
  backup: 'onboarding',
  check: 'onboarding',
  import: 'onboarding',
  lock: 'lock',
  home: 'wallet',
  // The other tabs beside Home.
  cards: 'wallet',
  activity: 'wallet',
  send: 'wallet',
  payment: 'wallet',
  receive: 'wallet',
  settings: 'wallet',
  'recovery-words': 'wallet',
  'check-words': 'wallet',
  vanish: 'wallet',
  summon: 'wallet',
  'wipe-card': 'wallet',
  'older-cards': 'wallet',
  // Ghost Sealed cards: Check, Fill and Open into the wallet. Fill pays from
  // the account and Open claims into it, so they are wallet screens.
  'check-card': 'wallet',
  'fill-card': 'wallet',
  'open-card': 'wallet',
  // Ghost Java cards: Fill pays from the account and Open summons into it.
  'fill-ghost-card': 'wallet',
  'open-ghost-card': 'wallet',
  // The feasibility bench holds only the public test words, and the device and
  // simulator scripts open it by link (ghostwallet://bench), so it stays
  // reachable without an account or unlock. Seven taps on the version in
  // Settings open it.
  bench: 'developer',
  // The Seal speed test: a bare test screen like the bench. It times a Check
  // through the Seal relay against a development test Seal and holds no
  // account secret.
  'seal-speed': 'developer',
  // The Java Card probe speed test: a bare test screen like the bench. It
  // talks only to the throwaway probe applet, with fixed test inputs, and
  // holds no account secret.
  'card-probe': 'developer',
} as const satisfies Record<string, RouteGroup>;

export type RouteName = keyof typeof ROUTE_GROUPS;

export function openGroups(state: AccountState): Record<RouteGroup, boolean> {
  return {
    onboarding: !state.hasAccount,
    lock: state.hasAccount && !state.unlocked,
    wallet: state.hasAccount && state.unlocked,
    developer: true,
  };
}

export function canOpen(route: RouteName, state: AccountState): boolean {
  return openGroups(state)[ROUTE_GROUPS[route]];
}

/** Where the app lands on open, and after a guard closes the current screen. */
export function landingRoute(state: AccountState): '/' | '/lock' | '/home' {
  if (!state.hasAccount) {
    return '/';
  }
  return state.unlocked ? '/home' : '/lock';
}

/** The state when the app opens: an account found in the Keychain starts locked. */
export function stateOnOpen(hasAccount: boolean): AccountState {
  return { hasAccount, unlocked: false };
}

/** The state right after the person creates or imports an account: they are in. */
export function stateAfterSave(): AccountState {
  return { hasAccount: true, unlocked: true };
}

/** The state after a passed unlock. Unlocking without an account changes nothing. */
export function stateAfterUnlock(state: AccountState): AccountState {
  return state.hasAccount ? { ...state, unlocked: true } : state;
}

/**
 * True when the wallet is open but the path still names a screen that has
 * closed (Welcome, the lock), so the app must move to Home itself.
 */
export function leftOnClosedScreen(pathname: string, state: AccountState): boolean {
  const open = openGroups(state);
  if (!open.wallet) {
    return false;
  }
  const name = pathname.split('/')[1] || 'index';
  return name in ROUTE_GROUPS && !open[ROUTE_GROUPS[name as RouteName]];
}
