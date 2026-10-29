import { quoteFee, signSend, type SendKit } from '../../lib/send/send-payment';
import { vanishNode } from '../../lib/vanish/node';
import type { SendDetails } from '../../lib/vanish/payments';

// A node whose blocks hold transactions. Asked for a block without them
// (`eth_getBlockByNumber` with `false`), it lists only their hashes, as a real
// node does.
const GENESIS = `0x${'47'.repeat(32)}`;
const TX_HASHES = [`0x${'11'.repeat(32)}`, `0x${'22'.repeat(32)}`];

type Call = { id: number; method: string; params: unknown[] };

function answer(call: Call): unknown {
  switch (call.method) {
    case 'eth_chainId':
      return '0x676c73';
    case 'eth_blockNumber':
      return '0x64';
    case 'eth_maxPriorityFeePerGas':
      return '0x3b9aca00';
    case 'eth_getBlockByNumber': {
      const [height, full] = call.params as [string, boolean];
      return {
        number: height,
        hash: GENESIS,
        baseFeePerGas: '0x1a13b8600',
        transactions: full ? [] : TX_HASHES,
      };
    }
    default:
      throw new Error(`unexpected call ${call.method}`);
  }
}

const fetchImpl = async (_url: string, init: RequestInit) => {
  const calls = JSON.parse(String(init.body)) as Call[];
  const body = calls.map((call) => ({ jsonrpc: '2.0', id: call.id, result: answer(call) }));
  return { ok: true, status: 200, json: async () => body } as Response;
};

const signSendCore = jest.fn((..._args: unknown[]) => ({
  transactionHash: new ArrayBuffer(32),
  sender: new ArrayBuffer(20),
  envelope: new Uint8Array([0x52, 0xab]).buffer,
}));

const kit = {
  core: { testChainId: () => 6777971n, testSendGasLimit: () => 84_256n, signSend: signSendCore },
  store: {},
  node: vanishNode('http://127.0.0.1:8547', fetchImpl),
  nodeUrl: 'http://127.0.0.1:8547',
} as unknown as SendKit;

describe('a tip block that holds transactions', () => {
  it('is read for its header: height, hash and base fee', async () => {
    const block = await kit.node.block(100);
    expect(block).toEqual({ height: 100, hash: GENESIS, baseFeePerGas: 7_000_000_000n, transactions: [] });
  });

  it('lets the fee be quoted', async () => {
    const quote = await quoteFee(kit);
    expect(quote.maxFeePerGas).toBe(15_000_000_000n);
    expect(quote.feeWei).toBe(15_000_000_000n * 84_256n);
  });

  it('lets the send be signed', async () => {
    const details: SendDetails = {
      kind: 'send',
      to: '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd',
      amountWei: '1000000000000000000',
      nonce: '3',
      maxFeePerGas: null,
      fromHeight: 90,
      at: 1,
    };
    const envelope = await signSend(kit, details);
    expect(new Uint8Array(envelope)).toEqual(new Uint8Array([0x52, 0xab]));
    expect(signSendCore).toHaveBeenCalledTimes(1);
    expect((signSendCore.mock.calls[0] as unknown as [Record<string, unknown>])[0]).toMatchObject({
      chainId: 6777971n,
      nonce: 3n,
      maxFeePerGas: 15_000_000_000n,
      maxPriorityFeePerGas: 1_000_000_000n,
    });
  });
});
