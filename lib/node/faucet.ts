// Test GHOST from the test chain's faucet (`bash scripts/test-chain.sh
// faucet`): a small endpoint next to the node that sends 10 test GHOST from
// one funded test account. The app only asks; it never holds the faucet's key.
import type { FetchLike } from './rpc';

export const FAUCET_PORT = 8548;

/** What one faucet request sends, in wei: 10 test GHOST. */
export const FAUCET_AMOUNT_WEI = 10n * 10n ** 18n;

const TIMEOUT_MS = 60_000;

/** The faucet beside the node at `nodeUrl`: the same host, port 8548. Null for an address that is not a URL. */
export function faucetUrlFor(nodeUrl: string): string | null {
  const match = /^(https?):\/\/(\[[^\]]+\]|[^/:?#\s]+)(?::\d+)?(?:[/?#]|$)/i.exec(nodeUrl.trim());
  if (!match) {
    return null;
  }
  return `${match[1].toLowerCase()}://${match[2]}:${FAUCET_PORT}/faucet`;
}

export type FaucetResult = {
  /** The transfer's hash, once it is in a block. */
  transactionHash: string;
};

/** A faucet failure, worded for the person. */
export class FaucetError extends Error {}

/**
 * Asks the faucet to send 10 test GHOST to `address`. The faucet answers
 * once the transfer is in a block, so the balance can be read right after.
 */
export async function requestTestGhost(nodeUrl: string, address: string, fetchImpl: FetchLike = fetch): Promise<FaucetResult> {
  const url = faucetUrlFor(nodeUrl);
  if (!url) {
    throw new FaucetError('The node address in Settings is not a web address.');
  }
  const host = url.replace(/^https?:\/\//, '').replace(/\/faucet$/, '');
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT_MS);
  let response: Response;
  let body: unknown = null;
  try {
    response = await fetchImpl(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ address }),
      signal: controller.signal,
    });
    try {
      body = await response.json();
    } catch {
      body = null;
    }
  } catch {
    throw new FaucetError(
      controller.signal.aborted
        ? `The test GHOST faucet at ${host} did not answer in time. Try again.`
        : `Can't reach the test GHOST faucet at ${host}. Check that it is running and this phone is on the same network.`,
    );
  } finally {
    clearTimeout(timer);
  }
  const answer = (typeof body === 'object' && body !== null ? body : {}) as { transactionHash?: unknown; error?: unknown };
  if (response.status === 429) {
    throw new FaucetError('Test GHOST was sent to this account less than a minute ago. Try again in a minute.');
  }
  if (!response.ok) {
    const reason = typeof answer.error === 'string' && answer.error.trim() !== '' ? answer.error.trim() : `HTTP ${response.status}`;
    throw new FaucetError(`The test GHOST faucet did not send any: ${reason}.`.replace(/\.\.$/, '.'));
  }
  if (typeof answer.transactionHash !== 'string' || !/^0x[0-9a-f]{64}$/i.test(answer.transactionHash)) {
    throw new FaucetError('The test GHOST faucet sent a malformed answer.');
  }
  return { transactionHash: answer.transactionHash.toLowerCase() };
}
