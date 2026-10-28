// Home's refresh: the node's tip, then the saved account's state at that tip
// through the native core's current-state lookup.
import { lookUpSavedAccount } from 'ghost-core';

import { getAccountState, getTip, type FetchLike } from '../node/rpc';
import type { AccountReading } from './cache-refresh';

/** Account 0's balance at the configured node; it must be the account home shows. */
export async function readAccountZero(nodeUrl: string, address: string, fetchImpl?: FetchLike): Promise<AccountReading> {
  const tip = await getTip(nodeUrl, fetchImpl);
  const account = await lookUpSavedAccount(0, tip, (accountAddress, blockHash) =>
    getAccountState(nodeUrl, accountAddress, blockHash, fetchImpl),
  );
  if (account.address.toLowerCase() !== address.toLowerCase()) {
    throw new Error('the core looked up another account');
  }
  return { balanceWei: account.balance, nonce: account.nonce, tipHeight: account.tipHeight };
}
