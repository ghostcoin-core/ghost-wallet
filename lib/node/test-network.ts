// Whether the configured node is this build's Ghost test network (chain
// 6777971 in dev builds, 6777972 in release builds): the only network where
// Home offers test GHOST from the faucet.
import { useEffect, useState } from 'react';

import { TEST_CHAIN_ID } from '../settings/settings';
import { getChainId, type FetchLike } from './rpc';

export const RECHECK_EVERY_MS = 20_000;

/**
 * True when the node at `nodeUrl` says it is the test network of the build
 * (`chainId`, this build's by default); false when it is another chain.
 */
export async function isTestNetwork(nodeUrl: string, fetchImpl?: FetchLike, chainId: bigint = TEST_CHAIN_ID): Promise<boolean> {
  return (await getChainId(nodeUrl, fetchImpl)) === chainId;
}

/**
 * Whether the node is the test network, asked when the address changes. Until
 * the node answers it is false, and it is asked again every 20 seconds.
 */
export function useTestNetwork(nodeUrl: string, check: (nodeUrl: string) => Promise<boolean> = isTestNetwork): boolean {
  const [known, setKnown] = useState<{ nodeUrl: string; test: boolean } | null>(null);

  useEffect(() => {
    let stopped = false;
    let timer: ReturnType<typeof setTimeout> | null = null;
    function ask() {
      check(nodeUrl).then(
        (test) => {
          if (!stopped) {
            setKnown({ nodeUrl, test });
          }
        },
        () => {
          if (!stopped) {
            timer = setTimeout(ask, RECHECK_EVERY_MS);
          }
        },
      );
    }
    ask();
    return () => {
      stopped = true;
      if (timer) {
        clearTimeout(timer);
      }
    };
  }, [nodeUrl, check]);

  return known?.nodeUrl === nodeUrl && known.test;
}
