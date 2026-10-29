// Home's "Get test GHOST": asks the test chain's faucet for 10 test GHOST
// and, once the transfer is in a block, reads the balance again.
import { useCallback, useState } from 'react';

import { FaucetError, requestTestGhost, type FaucetResult } from '../node/faucet';

export type FaucetState =
  | { name: 'idle' }
  | { name: 'asking' }
  | { name: 'sent' }
  | { name: 'failed'; message: string };

export function useFaucet(
  nodeUrl: string,
  address: string | null,
  refresh: () => void | Promise<void>,
  request: (nodeUrl: string, address: string) => Promise<FaucetResult> = requestTestGhost,
): { state: FaucetState; ask: () => Promise<void> } {
  const [state, setState] = useState<FaucetState>({ name: 'idle' });

  const ask = useCallback(async () => {
    if (!address) {
      return;
    }
    setState({ name: 'asking' });
    try {
      await request(nodeUrl, address);
    } catch (failure) {
      setState({
        name: 'failed',
        message: failure instanceof FaucetError ? failure.message : 'The test GHOST faucet did not send any.',
      });
      return;
    }
    setState({ name: 'sent' });
    // A refresh already in flight may have read the balance before the
    // transfer landed: the second one starts after it, so it sees it.
    await refresh();
    await refresh();
  }, [nodeUrl, address, refresh, request]);

  return { state, ask };
}
