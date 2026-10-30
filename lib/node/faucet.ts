// Test GHOST from the test chain's faucet (`bash scripts/test-chain.sh
// faucet`): a small endpoint next to the node that sends 10 test GHOST from
// one funded test account. Release builds ask the faucet beside each public
// test network node instead, at /ghost-faucet on the node's own host. The app
// only asks; it never holds the faucet's key.
import type { FetchLike } from './rpc';

export const FAUCET_PORT = 8548;

/** What one faucet request sends, in wei: 10 test GHOST. */
export const FAUCET_AMOUNT_WEI = 10n * 10n ** 18n;

const TIMEOUT_MS = 60_000;

/** The path a public node answers JSON-RPC on (RELEASE_NODE_URLS in lib/network/build-network.ts). */
export const NODE_RPC_PATH = '/ghost-rpc';

/** The path its faucet answers on, on the same host and port. */
export const FAUCET_PATH = '/ghost-faucet';

/**
 * The faucet beside the node at `nodeUrl`. A public node published at a path
 * (`https://host/ghost-rpc`) has its faucet on the same host and port at
 * `/ghost-faucet`, the only ports Tailscale Funnel serves; any other node (the
 * dev chain's `http://host:8547`) has it on the same host, port 8548. Null for
 * an address that is not a URL.
 */
export function faucetUrlFor(nodeUrl: string): string | null {
  const match = /^(https?):\/\/(\[[^\]]+\]|[^/:?#\s]+)(:\d+)?([/?#].*)?$/i.exec(nodeUrl.trim());
  if (!match) {
    return null;
  }
  const scheme = match[1].toLowerCase();
  const host = match[2];
  const path = (match[4] ?? '').split(/[?#]/)[0].replace(/\/+$/, '');
  if (path.toLowerCase() === NODE_RPC_PATH) {
    return `${scheme}://${host}${match[3] ?? ''}${FAUCET_PATH}`;
  }
  return `${scheme}://${host}:${FAUCET_PORT}/faucet`;
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
  const isPublic = url.endsWith(FAUCET_PATH);
  const host = url.replace(/^https?:\/\//, '').replace(isPublic ? FAUCET_PATH : /\/faucet$/, '');
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
        : isPublic
          ? `Can't reach the test GHOST faucet at ${host}. Check this phone's internet connection and try again.`
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
