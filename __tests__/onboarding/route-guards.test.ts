import fs from 'fs';
import path from 'path';

import {
  canOpen,
  landingRoute,
  openGroups,
  ROUTE_GROUPS,
  stateAfterSave,
  stateAfterUnlock,
  stateOnOpen,
  type AccountState,
  type RouteName,
} from '../../lib/onboarding/route-guards';

const NO_ACCOUNT: AccountState = { hasAccount: false, unlocked: false };
const LOCKED: AccountState = { hasAccount: true, unlocked: false };
const UNLOCKED: AccountState = { hasAccount: true, unlocked: true };

const ROUTES = Object.keys(ROUTE_GROUPS) as RouteName[];

function openRoutes(state: AccountState): RouteName[] {
  return ROUTES.filter((route) => canOpen(route, state));
}

describe('route guards', () => {
  it('without an account opens only onboarding and the bench', () => {
    expect(openRoutes(NO_ACCOUNT).sort()).toEqual(['backup', 'bench', 'check', 'import', 'index']);
  });

  it('with a locked account opens only the lock and the bench', () => {
    expect(openRoutes(LOCKED).sort()).toEqual(['bench', 'lock']);
  });

  it('with an unlocked account opens the wallet screens and the bench, and no onboarding screen', () => {
    expect(openRoutes(UNLOCKED).sort()).toEqual([
      'bench',
      'check-words',
      'home',
      'receive',
      'recovery-words',
      'settings',
      'summon',
      'vanish',
      'wipe-card',
    ]);
  });

  it('never opens Home without both an account and an unlock', () => {
    expect(canOpen('home', NO_ACCOUNT)).toBe(false);
    expect(canOpen('home', { hasAccount: false, unlocked: true })).toBe(false);
    expect(canOpen('home', LOCKED)).toBe(false);
  });

  it('opens exactly one of onboarding, lock and wallet in every state', () => {
    for (const hasAccount of [false, true]) {
      for (const unlocked of [false, true]) {
        const open = openGroups({ hasAccount, unlocked });
        expect([open.onboarding, open.lock, open.wallet].filter(Boolean)).toHaveLength(1);
        expect(open.developer).toBe(true);
      }
    }
  });

  it('gives every screen in app/ a group, so none is left unguarded', () => {
    const screens = fs
      .readdirSync(path.join(__dirname, '..', '..', 'app'))
      .filter((file) => file.endsWith('.tsx') && !file.startsWith('_'))
      .map((file) => file.replace(/\.tsx$/, ''));

    expect([...ROUTES].sort()).toEqual(screens.sort());
  });
});

describe('landing route', () => {
  it('lands on Welcome, the lock or Home', () => {
    expect(landingRoute(NO_ACCOUNT)).toBe('/');
    expect(landingRoute(LOCKED)).toBe('/lock');
    expect(landingRoute(UNLOCKED)).toBe('/home');
  });

  it('is always a route its state can open', () => {
    const routeOf = { '/': 'index', '/lock': 'lock', '/home': 'home' } as const;
    for (const state of [NO_ACCOUNT, LOCKED, UNLOCKED]) {
      expect(canOpen(routeOf[landingRoute(state)], state)).toBe(true);
    }
  });
});

describe('state changes', () => {
  it('starts locked when the Keychain holds an account', () => {
    expect(stateOnOpen(true)).toEqual(LOCKED);
    expect(stateOnOpen(false)).toEqual(NO_ACCOUNT);
  });

  it('lets the person straight in after they create or import an account', () => {
    expect(stateAfterSave()).toEqual(UNLOCKED);
  });

  it('unlocks a saved account, and nothing without one', () => {
    expect(stateAfterUnlock(LOCKED)).toEqual(UNLOCKED);
    expect(stateAfterUnlock(NO_ACCOUNT)).toEqual(NO_ACCOUNT);
  });
});
