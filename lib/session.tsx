import { createContext, useCallback, useContext, useMemo, useState, type ReactNode } from 'react';

import { hasAccount } from '../modules/ghost-core';
import {
  stateAfterSave,
  stateAfterUnlock,
  stateOnOpen,
  type AccountState,
} from './onboarding/route-guards';

type Session = AccountState & {
  /** Call after the core saved new or imported words. */
  accountSaved(): void;
  /** Call after Face ID or the passcode passed. */
  unlock(): void;
};

const SessionContext = createContext<Session | null>(null);

export function SessionProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<AccountState>(() => stateOnOpen(hasAccount()));
  const accountSaved = useCallback(() => setState(stateAfterSave()), []);
  const unlock = useCallback(() => setState(stateAfterUnlock), []);
  const session = useMemo(() => ({ ...state, accountSaved, unlock }), [state, accountSaved, unlock]);
  return <SessionContext.Provider value={session}>{children}</SessionContext.Provider>;
}

export function useSession(): Session {
  const session = useContext(SessionContext);
  if (session === null) {
    throw new Error('useSession must be used inside SessionProvider');
  }
  return session;
}
