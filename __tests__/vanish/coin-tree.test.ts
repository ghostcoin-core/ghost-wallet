import { spentBuffers, type CoinTree } from '../../lib/vanish/coin-tree';
import { bytesToHex } from '../../modules/ghost-core/account-lookup';

const marker = (byte: string) => `0x${byte.repeat(32)}`;

describe('the coin tree a Summon uses', () => {
  it('hands its spent markers to the core as bytes, in order', () => {
    const tree: CoinTree = { height: 3, hash: marker('aa'), leaves: [], spent: [marker('01'), marker('02')], spentBy: {} };
    expect(spentBuffers(tree).map((bytes) => bytesToHex(new Uint8Array(bytes)))).toEqual([marker('01'), marker('02')]);
  });

  it('hands none when no marker is known', () => {
    expect(spentBuffers({ height: 0, hash: '', leaves: [], spent: [], spentBy: {} })).toEqual([]);
  });
});
