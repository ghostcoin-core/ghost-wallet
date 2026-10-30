import fs from 'fs';
import path from 'path';

import { act, fireEvent, render, screen } from '@testing-library/react-native';

import HomeScreen from '../../app/home';
import type { AccountReading } from '../../lib/home/cache-refresh';
import { FAUCET_AMOUNT_WEI, FaucetError, requestTestGhost } from '../../lib/node/faucet';

const ADDRESS = '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd';
const NODE = 'http://192.168.1.36:8547';
const TX = '0x' + 'ab'.repeat(32);
const GHOST = 10n ** 18n;

function answer(status: number, body: unknown): Response {
  return { ok: status >= 200 && status < 300, status, json: async () => body } as unknown as Response;
}

describe('requestTestGhost', () => {
  it('POSTs the address to the faucet beside the node and returns the transfer', async () => {
    const fetchImpl = jest.fn(async () => answer(200, { transactionHash: TX.toUpperCase().replace('0X', '0x') }));

    await expect(requestTestGhost(NODE, ADDRESS, fetchImpl)).resolves.toEqual({ transactionHash: TX });

    expect(fetchImpl).toHaveBeenCalledTimes(1);
    const [url, init] = fetchImpl.mock.calls[0] as unknown as [string, RequestInit];
    expect(url).toBe('http://192.168.1.36:8548/faucet');
    expect(init.method).toBe('POST');
    expect(JSON.parse(String(init.body))).toEqual({ address: ADDRESS });
  });

  it('asks for 10 test GHOST', () => {
    expect(FAUCET_AMOUNT_WEI).toBe(10n * GHOST);
  });

  it('says when the faucet cannot be reached', async () => {
    const fetchImpl = jest.fn(async () => {
      throw new TypeError('Network request failed');
    });
    await expect(requestTestGhost(NODE, ADDRESS, fetchImpl)).rejects.toThrow(
      "Can't reach the test GHOST faucet at 192.168.1.36:8548",
    );
  });

  it('asks a public node’s faucet at /ghost-faucet and says to check the internet when it cannot reach it', async () => {
    const ok = jest.fn(async () => answer(200, { transactionHash: TX }));
    await expect(requestTestGhost('https://kipp-vm.tail11407b.ts.net/ghost-rpc', ADDRESS, ok)).resolves.toEqual({ transactionHash: TX });
    expect((ok.mock.calls[0] as unknown as [string])[0]).toBe('https://kipp-vm.tail11407b.ts.net/ghost-faucet');

    const down = jest.fn(async () => {
      throw new TypeError('Network request failed');
    });
    await expect(requestTestGhost('https://kipp-vm.tail11407b.ts.net/ghost-rpc', ADDRESS, down)).rejects.toThrow(
      "Can't reach the test GHOST faucet at kipp-vm.tail11407b.ts.net. Check this phone's internet connection",
    );
  });

  it('says to wait a minute when the address asked already', async () => {
    const fetchImpl = jest.fn(async () => answer(429, { error: 'once a minute' }));
    await expect(requestTestGhost(NODE, ADDRESS, fetchImpl)).rejects.toThrow('Try again in a minute.');
  });

  it("passes on the faucet's reason", async () => {
    const fetchImpl = jest.fn(async () => answer(502, { error: 'insufficient funds for transfer' }));
    const failure = requestTestGhost(NODE, ADDRESS, fetchImpl);
    await expect(failure).rejects.toBeInstanceOf(FaucetError);
    await expect(failure).rejects.toThrow('The test GHOST faucet did not send any: insufficient funds for transfer.');
  });

  it('refuses a malformed answer', async () => {
    const fetchImpl = jest.fn(async () => answer(200, { transactionHash: 'nope' }));
    await expect(requestTestGhost(NODE, ADDRESS, fetchImpl)).rejects.toThrow('malformed');
  });
});

// The endpoint of `bash scripts/test-chain.sh faucet`, loaded from the script.
type Faucet = {
  handle(method: string, path: string, text: string): Promise<{ status: number; json: Record<string, string> }>;
};
type FaucetModule = {
  FAUCET_WEI: bigint;
  ONCE_EVERY_MS: number;
  createFaucet(options: {
    from: string;
    rpc: (method: string, params: unknown[]) => Promise<unknown>;
    now?: () => number;
    sleep?: (ms: number) => Promise<void>;
    receiptTries?: number;
  }): Faucet;
};

const script = fs.readFileSync(path.join(__dirname, '..', '..', 'scripts/test-chain.sh'), 'utf8');

function loadFaucet(): FaucetModule {
  const open = "faucet_js() {\n  cat <<'FAUCET'\n";
  const start = script.indexOf(open);
  expect(start).toBeGreaterThanOrEqual(0);
  const end = script.indexOf('\nFAUCET\n', start);
  expect(end).toBeGreaterThan(start);
  const exported = {} as FaucetModule;
  // No faucet-main argument: the program only defines its functions.
  new Function('exports', 'process', 'require', script.slice(start + open.length, end))(exported, { argv: ['node'] }, () => {
    throw new Error('the faucet loads no module unless it serves');
  });
  return exported;
}

describe('the faucet endpoint in scripts/test-chain.sh', () => {
  const MINER = '0x' + '11'.repeat(20);
  const faucetModule = loadFaucet();

  function setUp(sendResult: () => unknown = () => TX) {
    let clock = 1_000_000;
    const calls: [string, unknown[]][] = [];
    const rpc = jest.fn(async (method: string, params: unknown[]) => {
      calls.push([method, params]);
      if (method === 'eth_sendTransaction') return sendResult();
      if (method === 'eth_getTransactionReceipt') return { blockNumber: '0x10', status: '0x1' };
      throw new Error(`unexpected ${method}`);
    });
    const faucet = faucetModule.createFaucet({ from: MINER, rpc, now: () => clock, sleep: async () => {} });
    return { faucet, calls, advance: (ms: number) => (clock += ms) };
  }

  it('is a command of the script, on port 8548', () => {
    expect(script).toMatch(/^  faucet\) cmd_faucet "\$@" ;;$/m);
    expect(script).toMatch(/^FAUCET_PORT=8548$/m);
    expect(script).toContain('node -e "$(faucet_js)" faucet-main "$RPC" "$miner" "$FAUCET_PORT"');
    expect(script).toContain("server.listen(Number(port), '0.0.0.0')");
  });

  it('sends 10 GHOST from the faucet account to the POSTed address, once it is in a block', async () => {
    const { faucet, calls } = setUp();
    const result = await faucet.handle('POST', '/faucet', JSON.stringify({ address: ADDRESS.toUpperCase().replace('0X', '0x') }));

    expect(result).toEqual({ status: 200, json: { transactionHash: TX } });
    expect(calls[0]).toEqual(['eth_sendTransaction', [{ from: MINER, to: ADDRESS, value: '0x8ac7230489e80000' }]]);
    expect(BigInt('0x8ac7230489e80000')).toBe(10n * GHOST);
    expect(faucetModule.FAUCET_WEI).toBe(10n * GHOST);
    expect(calls[1]).toEqual(['eth_getTransactionReceipt', [TX]]);
  });

  it('sends to each address at most once a minute', async () => {
    const { faucet, calls, advance } = setUp();
    const body = JSON.stringify({ address: ADDRESS });
    expect((await faucet.handle('POST', '/faucet', body)).status).toBe(200);

    advance(59_000);
    const again = await faucet.handle('POST', '/faucet', body);
    expect(again.status).toBe(429);
    expect(calls.filter(([method]) => method === 'eth_sendTransaction')).toHaveLength(1);

    // Another address is not held up.
    const other = JSON.stringify({ address: '0x' + '22'.repeat(20) });
    expect((await faucet.handle('POST', '/faucet', other)).status).toBe(200);

    advance(1_000);
    expect((await faucet.handle('POST', '/faucet', body)).status).toBe(200);
  });

  it('refuses what is not an address, and other paths and methods', async () => {
    const { faucet, calls } = setUp();
    expect((await faucet.handle('POST', '/faucet', '{"address":"0x12"}')).status).toBe(400);
    expect((await faucet.handle('POST', '/faucet', 'not json')).status).toBe(400);
    expect((await faucet.handle('GET', '/faucet', '')).status).toBe(405);
    expect((await faucet.handle('POST', '/', JSON.stringify({ address: ADDRESS }))).status).toBe(404);
    expect(calls).toHaveLength(0);
  });

  it("passes on the node's refusal and lets the address ask again at once", async () => {
    let refuse = true;
    const { faucet } = setUp(() => {
      if (refuse) throw new Error('insufficient funds for gas * price + value');
      return TX;
    });
    const body = JSON.stringify({ address: ADDRESS });

    expect(await faucet.handle('POST', '/faucet', body)).toEqual({
      status: 502,
      json: { error: 'insufficient funds for gas * price + value' },
    });
    refuse = false;
    expect((await faucet.handle('POST', '/faucet', body)).status).toBe(200);
  });
});

// Home on the test network: the button, the faucet and the balance after it.
const mockPush = jest.fn();
jest.mock('expo-router', () => ({ useRouter: () => ({ push: mockPush, back: jest.fn() }) }));
jest.mock(
  '../../modules/ghost-core/src/index',
  () => ({ savedAccountZeroAddress: () => '0xe5fbe4d8256744ec6fd55f2ce5bdfae7cbf355fd' }),
  { virtual: true },
);
jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => null, write: async () => {} }) }));

let mockReading: () => Promise<AccountReading>;
jest.mock('../../lib/home/read-account', () => ({ readAccountZero: () => mockReading() }));

let mockChainId: () => Promise<bigint>;
jest.mock('../../lib/node/rpc', () => ({
  ...jest.requireActual('../../lib/node/rpc'),
  getChainId: () => mockChainId(),
}));

describe('Get test GHOST on Home', () => {
  const realFetch = global.fetch;
  let mockFetch: jest.Mock;

  beforeEach(() => {
    mockReading = async () => ({ balanceWei: '0', nonce: 0, tipHeight: 50 });
    mockChainId = async () => 6777971n;
    mockFetch = jest.fn(async () => answer(200, { transactionHash: TX }));
    global.fetch = mockFetch as unknown as typeof fetch;
  });

  afterEach(() => {
    global.fetch = realFetch;
  });

  it('shows on the test network and puts 10 test GHOST in the balance', async () => {
    render(<HomeScreen />);
    await act(async () => {});
    expect(screen.getByTestId('balance-amount')).toHaveTextContent('0.00 GHOST');

    // The faucet sends: the next read of the node holds the 10 GHOST.
    mockReading = async () => ({ balanceWei: (10n * GHOST).toString(), nonce: 0, tipHeight: 52 });
    await act(async () => {
      fireEvent.press(screen.getByTestId('get-test-ghost'));
    });

    expect(mockFetch).toHaveBeenCalledWith('http://192.168.1.36:8548/faucet', expect.objectContaining({ method: 'POST' }));
    const [, init] = mockFetch.mock.calls[0] as [string, RequestInit];
    expect(JSON.parse(String(init.body))).toEqual({ address: ADDRESS });
    expect(screen.getByTestId('balance-amount')).toHaveTextContent('10.00 GHOST');
    expect(screen.getByTestId('faucet-status')).toHaveTextContent(/^10 test GHOST arrived\./);
  });

  it('says why when the faucet sends nothing', async () => {
    mockFetch.mockImplementation(async () => {
      throw new TypeError('Network request failed');
    });
    render(<HomeScreen />);
    await act(async () => {});

    await act(async () => {
      fireEvent.press(screen.getByTestId('get-test-ghost'));
    });

    expect(screen.getByTestId('faucet-status')).toHaveTextContent(/^Can't reach the test GHOST faucet at 192\.168\.1\.36:8548\./);
  });

  it('is not shown on another chain', async () => {
    mockChainId = async () => 1n;
    render(<HomeScreen />);
    await act(async () => {});
    expect(screen.queryByTestId('get-test-ghost')).toBeNull();
  });

  it('is not shown before the node says which chain it is', async () => {
    mockChainId = () => new Promise(() => {});
    render(<HomeScreen />);
    await act(async () => {});
    expect(screen.queryByTestId('get-test-ghost')).toBeNull();
  });
});
