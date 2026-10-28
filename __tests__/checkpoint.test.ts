import fs from 'fs';
import path from 'path';

// The checkpoint builder of `scripts/test-chain.sh checkpoint <height>`: the
// Node program the script runs, loaded here from the script's own text. Its
// header encoding is checked against Ghost's golden header vectors (spec 05,
// section 11) and its key-block selection against Ghost's seed_height.
const ROOT = path.join(__dirname, '..');

function read(relative: string): string {
  return fs.readFileSync(path.join(ROOT, relative), 'utf8');
}

type Block = Record<string, unknown>;
type Checkpoint = {
  rlpHex: string;
  height: number;
  totalWorkHex: string;
  genesisTimestamp: number;
  keyBlocks: { height: number; hashHex: string }[];
};
type Builder = {
  EPOCH_BLOCKS: number;
  EPOCH_LAG: number;
  HEADER_FIELDS: [string, string, number][];
  seedHeight: (height: number) => number;
  keyBlockHeights: (height: number, tip: number) => number[];
  encodeHeader: (block: Block) => string;
  buildCheckpoint: (
    height: number,
    tip: number,
    getBlocks: (from: number, through: number) => Promise<Block[]>,
  ) => Promise<Checkpoint>;
};

const script = read('scripts/test-chain.sh');

function loadBuilder(): Builder {
  const open = "checkpoint_js() {\n  cat <<'JS'\n";
  const start = script.indexOf(open);
  expect(start).toBeGreaterThanOrEqual(0);
  const end = script.indexOf('\nJS\n', start);
  expect(end).toBeGreaterThan(start);
  const source = script.slice(start + open.length, end);
  const exported = {} as Builder;
  // No checkpoint-main argument: the program only defines its functions.
  new Function('exports', 'process', source)(exported, { argv: ['node'] });
  return exported;
}

const builder = loadBuilder();
const fixture = JSON.parse(read('__tests__/fixtures/checkpoint-headers.json')) as {
  blocks: Block[];
  rlp: string[];
};
const [genesis, blockOne] = fixture.blocks;

// A third block on top of block one, for a tip above the checkpoint.
const blockTwo: Block = {
  ...blockOne,
  parentHash: blockOne.hash,
  number: '0x2',
  hash: '0x' + '77'.repeat(32),
};

function chain(blocks: Block[]) {
  const calls: [number, number][] = [];
  const getBlocks = async (from: number, through: number) => {
    calls.push([from, through]);
    return blocks.slice(from, through + 1);
  };
  return { calls, getBlocks };
}

describe('the header encoding', () => {
  it('encodes the 19 fields in the order, kinds and sizes of HeaderSyncBenchmark.swift', () => {
    const swift = read('modules/ghost-bench/ios/Benchmarks/HeaderSyncBenchmark.swift');
    const list = swift.slice(swift.indexOf('static let fields'), swift.indexOf('static func encode'));
    const fields = [...list.matchAll(/\("(\w+)", \.(\w+), (\d+)\)/g)].map(([, name, kind, size]) => [
      name,
      kind,
      Number(size),
    ]);
    expect(fields).toHaveLength(19);
    expect(builder.HEADER_FIELDS).toEqual(fields);
  });

  it("matches Ghost's golden RLP of the genesis and block one examples", () => {
    expect(builder.encodeHeader(genesis)).toBe(fixture.rlp[0]);
    expect(builder.encodeHeader(blockOne)).toBe(fixture.rlp[1]);
  });

  it('writes integers without leading zeros and takes odd-digit quantities', () => {
    const padded = { ...blockOne, gasUsed: '0x0001ec30', baseFeePerGas: '0x0342770c0' };
    expect(builder.encodeHeader(padded)).toBe(fixture.rlp[1]);
  });

  it('refuses a header with a missing, short or non-hex field', () => {
    const missing = { ...blockOne };
    delete missing.mixHash;
    expect(() => builder.encodeHeader(missing)).toThrow(/no mixHash/);
    expect(() => builder.encodeHeader({ ...blockOne, miner: '0x' + '00'.repeat(19) })).toThrow(
      /miner is not 20 bytes/,
    );
    expect(() => builder.encodeHeader({ ...blockOne, stateRoot: '0x' + 'zz'.repeat(32) })).toThrow(
      /stateRoot is not hex/,
    );
    expect(() => builder.encodeHeader({ ...blockOne, extraData: '0x' + '01'.repeat(33) })).toThrow(
      /extraData is longer/,
    );
    expect(() => builder.encodeHeader({ ...blockOne, number: '0x1' + '00'.repeat(8) })).toThrow(
      /number is out of range/,
    );
  });
});

describe('the key-block selection', () => {
  it("uses Ghost's epoch length and lag", () => {
    expect(builder.EPOCH_BLOCKS).toBe(8192);
    expect(builder.EPOCH_LAG).toBe(256);
  });

  it("follows Ghost's seed_height: a key block is first used 257 blocks after it", () => {
    expect(builder.seedHeight(0)).toBe(0);
    expect(builder.seedHeight(8448)).toBe(0);
    expect(builder.seedHeight(8449)).toBe(8192);
    expect(builder.seedHeight(16640)).toBe(8192);
    expect(builder.seedHeight(16641)).toBe(16384);
  });

  it('pins the key blocks at or below the checkpoint that the headers after it use', () => {
    // A checkpoint at 8000: the headers up to 8448 use block 0; from 8449 they
    // use 8192, above the checkpoint, which a header sync checks itself.
    expect(builder.keyBlockHeights(8000, 8600)).toEqual([0]);
    // A checkpoint 1,000 below a tip of 8600.
    expect(builder.keyBlockHeights(7600, 8600)).toEqual([0]);
    // Past the second key's first use, only 8192 is used.
    expect(builder.keyBlockHeights(8499, 8700)).toEqual([8192]);
    // A checkpoint at a key block may pin it, and headers on both sides of
    // 8449 use both keys.
    expect(builder.keyBlockHeights(8192, 9000)).toEqual([0, 8192]);
    expect(builder.keyBlockHeights(8448, 8449)).toEqual([8192]);
    expect(builder.keyBlockHeights(8447, 8448)).toEqual([0]);
    expect(builder.keyBlockHeights(20000, 25000)).toEqual([16384]);
    expect(builder.keyBlockHeights(100, 200)).toEqual([0]);
  });
});

describe('the checkpoint', () => {
  it('pins the header, total work, genesis timestamp and key blocks of the fixture chain', async () => {
    const { calls, getBlocks } = chain([genesis, blockOne, blockTwo]);
    const checkpoint = await builder.buildCheckpoint(1, 2, getBlocks);
    expect(calls).toEqual([[0, 1]]);
    expect(checkpoint).toEqual({
      rlpHex: fixture.rlp[1],
      height: 1,
      // Two headers of difficulty 2^24, from block 0.
      totalWorkHex: (2n * 16777216n).toString(16).padStart(64, '0'),
      genesisTimestamp: 1798767600,
      keyBlocks: [{ height: 0, hashHex: '039d14f59db29e2e76c8ed76f90b70de42e48f8a67dba060b363501af50e3ba4' }],
    });
    // The five fields, in that order, as HeaderSync.fromCheckpoint takes them.
    expect(Object.keys(checkpoint)).toEqual([
      'rlpHex',
      'height',
      'totalWorkHex',
      'genesisTimestamp',
      'keyBlocks',
    ]);
    expect(JSON.parse(JSON.stringify(checkpoint))).toEqual(checkpoint);
  });

  it('sums every header difficulty from block 0', async () => {
    const heavy = { ...blockOne, difficulty: '0x1' + '00'.repeat(20) };
    const { getBlocks } = chain([genesis, heavy, blockTwo]);
    const checkpoint = await builder.buildCheckpoint(1, 2, getBlocks);
    expect(BigInt('0x' + checkpoint.totalWorkHex)).toBe(16777216n + (1n << 160n));
    expect(checkpoint.totalWorkHex).toHaveLength(64);
  });

  it('refuses a chain that does not link, a block at the wrong height or a missing block', async () => {
    const unlinked = { ...blockOne, parentHash: '0x' + '55'.repeat(32) };
    await expect(builder.buildCheckpoint(1, 2, chain([genesis, unlinked]).getBlocks)).rejects.toThrow(
      /block 1 does not link to block 0/,
    );
    const misnumbered = { ...blockOne, number: '0x5' };
    await expect(builder.buildCheckpoint(1, 2, chain([genesis, misnumbered]).getBlocks)).rejects.toThrow(
      /block 1 carries another height/,
    );
    await expect(builder.buildCheckpoint(1, 2, chain([genesis]).getBlocks)).rejects.toThrow(
      /did not return every block/,
    );
  });

  it('is between block 1 and the tip, exclusive', async () => {
    const { getBlocks } = chain([genesis, blockOne, blockTwo]);
    await expect(builder.buildCheckpoint(0, 2, getBlocks)).rejects.toThrow(/between 1 and the tip/);
    await expect(builder.buildCheckpoint(2, 2, getBlocks)).rejects.toThrow(/between 1 and the tip/);
  });
});

describe('scripts/test-chain.sh checkpoint', () => {
  it('runs the builder with the node URL, the height and the tip', () => {
    expect(script).toMatch(/^  checkpoint\) cmd_checkpoint "\$@" ;;$/m);
    expect(script).toContain('node -e "$(checkpoint_js)" checkpoint-main "$RPC" "$1" "$tip"');
  });
});
