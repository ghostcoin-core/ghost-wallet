import { SEND_TIMEOUT_MS, TIMEOUT_MS, isRefusal, rpcBatch, type FetchLike } from '../../lib/node/rpc';
import { vanishNode } from '../../lib/vanish/node';

const URL = 'http://127.0.0.1:8547';
const SENT = `0x${'cc'.repeat(32)}`;

type Call = { id: number; method: string };

/** A node that answers each batch after `delayMs`, and drops it when the request is aborted. */
function slowNode(delayMs: number, answer: (call: Call) => unknown) {
  const fetchImpl = jest.fn(
    (_url: string, init: RequestInit) =>
      new Promise<Response>((resolve, reject) => {
        const calls = JSON.parse(String(init.body)) as Call[];
        const timer = setTimeout(() => {
          resolve({
            ok: true,
            status: 200,
            json: async () => calls.map((call) => ({ jsonrpc: '2.0', id: call.id, result: answer(call) })),
          } as unknown as Response);
        }, delayMs);
        init.signal?.addEventListener('abort', () => {
          clearTimeout(timer);
          reject(new Error('Aborted'));
        });
      }),
  );
  return fetchImpl as jest.Mock & FetchLike;
}

function answers(call: Call): unknown {
  return call.method === 'eth_sendRawTransaction' ? SENT : '0x64';
}

/** Settles `promise` after `ms` of fake time, keeping its outcome. */
async function after<T>(ms: number, promise: Promise<T>): Promise<{ value?: T; error?: unknown }> {
  const outcome = promise.then(
    (value) => ({ value }),
    (error: unknown) => ({ error }),
  );
  await jest.advanceTimersByTimeAsync(ms);
  return outcome;
}

beforeEach(() => {
  jest.useFakeTimers();
});

afterEach(() => {
  jest.useRealTimers();
});

describe('the send time limit', () => {
  it('covers a large upload on a slow phone link, and reads keep theirs', () => {
    expect(SEND_TIMEOUT_MS).toBeGreaterThanOrEqual(90_000);
    expect(TIMEOUT_MS).toBe(10_000);
  });

  it('lets a send slower than a read’s limit, within the send limit, succeed', async () => {
    const fetchImpl = slowNode(45_000, answers);
    const node = vanishNode(URL, fetchImpl);
    const outcome = await after(45_000, node.sendRaw('0x0201'));
    expect(outcome.error).toBeUndefined();
    expect(outcome.value).toBe(SENT);
    expect(fetchImpl).toHaveBeenCalledTimes(1);
  });

  it('still stops a send that takes longer than the send limit', async () => {
    const node = vanishNode(URL, slowNode(SEND_TIMEOUT_MS + 5_000, answers));
    const outcome = await after(SEND_TIMEOUT_MS + 1, node.sendRaw('0x0201'));
    expect(String(outcome.error)).toMatch(/did not answer in time/);
    expect(isRefusal(outcome.error)).toBe(false);
  });

  it('keeps a read to its 10 s limit', async () => {
    const node = vanishNode(URL, slowNode(15_000, answers));
    const outcome = await after(TIMEOUT_MS + 1, node.tipHeight());
    expect(String(outcome.error)).toMatch(/did not answer in time/);
  });

  it('keeps rpcBatch to the read limit unless told otherwise', async () => {
    const outcome = await after(TIMEOUT_MS + 1, rpcBatch(URL, [['eth_blockNumber', []]], slowNode(15_000, answers)));
    expect(String(outcome.error)).toMatch(/did not answer in time/);
  });
});

describe('a refusal', () => {
  it('is told apart from a timeout or a dropped connection', async () => {
    const refusing = jest.fn(async (_url: string, init: RequestInit) => {
      const [call] = JSON.parse(String(init.body)) as Call[];
      return {
        ok: true,
        status: 200,
        json: async () => [{ jsonrpc: '2.0', id: call.id, error: { message: 'invalid sender' } }],
      } as unknown as Response;
    });
    const refused = await after(0, vanishNode(URL, refusing).sendRaw('0x0201'));
    expect(isRefusal(refused.error)).toBe(true);

    const dropped = jest.fn(async () => {
      throw new TypeError('Network request failed');
    });
    const lost = await after(0, vanishNode(URL, dropped).sendRaw('0x0201'));
    expect(lost.error).toBeInstanceOf(TypeError);
    expect(isRefusal(lost.error)).toBe(false);
  });
});
