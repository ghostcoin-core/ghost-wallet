// The saved card changes (lib/ghost-card/vault.ts, fileChanges): a change
// saved by an earlier build, before a change said whether its old coin
// counted, is read as counting it and is never dropped.
import { fileChanges } from '../../lib/ghost-card/vault';

const mockSaved = [
  {
    id: 'change-1',
    cardId: '0x11',
    cardNumber: 'CARD',
    oldFill: 1,
    oldMarker: '0x' + 'ab'.repeat(32),
    oldCommitData: null,
    beforeWei: '5',
    afterWei: '15',
    commitData: null,
    newFill: null,
    summonId: null,
    vanishId: null,
    at: 1,
  },
  { id: 'broken' },
];

jest.mock('../../lib/storage', () => ({ jsonFile: () => ({ read: () => mockSaved, write: async () => {} }) }));

it('reads an older saved change as counting its old coin, and drops only what does not read', () => {
  const changes = fileChanges().read();
  expect(changes).toHaveLength(1);
  expect(changes[0]).toMatchObject({ id: 'change-1', oldCounted: true, afterWei: '15' });
});
