// Errors from the node layer name the node that failed: a backup node the
// coin tree was read from, not only the node in Settings.
import { failureReason } from '../../lib/node/failure-reason';
import { failedNodeUrl, getChainId, getTip, rpcBatch, type FetchLike } from '../../lib/node/rpc';
import { readCoinTreeFrom, type PagesCore } from '../../lib/vanish/coin-pages';
import { vanishNode, type VanishNode } from '../../lib/vanish/node';
import { buildNetwork } from '../../lib/network/build-network';

const SETTINGS = 'http://settings-node.test:8545';
const BACKUP = 'http://backup-node.test:8545';

/** A node that never answers, until the call is given up. */
const silent: FetchLike = (_url, init) =>
  new Promise((_, reject) => {
    init.signal?.addEventListener('abort', () => reject(new Error('Aborted')));
  });

const answering =
  (answer: (call: { id: number; method: string }) => unknown): FetchLike =>
  async (_url, init) => {
    const calls = JSON.parse(init.body as string) as { id: number; method: string }[];
    return { ok: true, status: 200, json: async () => calls.map((call) => ({ jsonrpc: '2.0', id: call.id, ...(answer(call) as object) })) } as Response;
  };

async function failure(run: () => Promise<unknown>): Promise<unknown> {
  try {
    await run();
  } catch (error) {
    return error;
  }
  throw new Error('expected a failure');
}

describe('an error from the node layer', () => {
  it('names the backup node when the backup node times out', async () => {
    const error = await failure(() => rpcBatch(BACKUP, [['eth_chainId', []]], silent, 5));
    expect((error as Error).message).toBe('the node did not answer in time');
    expect(failedNodeUrl(error)).toBe(BACKUP);
    const reason = failureReason(error, SETTINGS);
    expect(reason).toBe(`The test node at ${BACKUP} did not answer in time. Check that it is running and try again.`);
    expect(reason).not.toContain(SETTINGS);
  });

  it('names the node it could not reach, the node that refused and the node that sent a malformed answer', async () => {
    const unreachable = await failure(() =>
      rpcBatch(BACKUP, [['eth_chainId', []]], async () => {
        throw new TypeError('Network request failed');
      }),
    );
    expect(failureReason(unreachable, SETTINGS)).toBe(
      `Can't reach the test node at ${BACKUP}. Check that it is running and that this phone is on the same network.`,
    );

    const refused = await failure(() => rpcBatch(BACKUP, [['eth_chainId', []]], answering(() => ({ error: { message: 'busy' } }))));
    expect(failureReason(refused, SETTINGS)).toBe(`The test node at ${BACKUP} refused it: busy.`);

    const http = await failure(() => rpcBatch(BACKUP, [['eth_chainId', []]], async () => ({ ok: false, status: 502 }) as Response));
    expect(failureReason(http, SETTINGS)).toBe(`The test node at ${BACKUP} answered with an error (HTTP 502).`);

    const malformed = await failure(() => getChainId(BACKUP, answering(() => ({ result: 'nope' }))));
    expect(failureReason(malformed, SETTINGS)).toBe(`The test node at ${BACKUP} sent an answer this app cannot read.`);

    const badTip = await failure(() => getTip(BACKUP, answering(() => ({ result: { number: '0x1', hash: 'nope' } }))));
    expect(failedNodeUrl(badTip)).toBe(BACKUP);
  });

  it('names the node in Settings when the error does not say which node', () => {
    expect(failureReason(new Error('the node did not answer in time'), SETTINGS)).toBe(
      `The test node at ${SETTINGS} did not answer in time. Check that it is running and try again.`,
    );
  });

  it('names the node a call went to, through the Vanish node client', async () => {
    const error = await failure(() => vanishNode(BACKUP, async () => {
      throw new TypeError('Network request failed');
    }).chainId());
    expect(failedNodeUrl(error)).toBe(BACKUP);
  });
});

describe('the coin tree read from the next node', () => {
  const core = { checkCoinPages: jest.fn(), noteBucketBits: jest.fn(), keyNoteBuckets: jest.fn(), keyBucketPositions: jest.fn() } as unknown as PagesCore;
  const cache = { load: () => null, save: () => undefined };

  it('names the backup node when it is the backup node that timed out', async () => {
    // The node in Settings errs without saying which node (as a node client
    // that is not the JSON-RPC one may); the backup node times out.
    const first = { url: SETTINGS, anchor: async () => Promise.reject(new Error('the node did not answer in time')) } as unknown as VanishNode;
    const timesOut = () => rpcBatch(BACKUP, [['eth_chainId', []]], silent, 5);
    const backup = { url: BACKUP, chainId: timesOut, anchor: timesOut } as unknown as VanishNode;
    const fromSettings = await failure(() => readCoinTreeFrom(core, [first, backup], cache, buildNetwork.chainId));
    expect(failedNodeUrl(fromSettings)).toBe(SETTINGS);

    const onlyBackup = await failure(() => readCoinTreeFrom(core, [backup], cache, buildNetwork.chainId));
    expect(failureReason(onlyBackup, SETTINGS)).toBe(
      `The test node at ${BACKUP} did not answer in time. Check that it is running and try again.`,
    );
  });
});
