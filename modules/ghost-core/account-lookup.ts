// One account's balance through the native core's current-state lookup
// (`RestoreLookup` in core/src/restore_scan.rs).
//
// The core's lookup callback is synchronous, and a node answers
// asynchronously. So the core first derives the account's address, the node
// is asked for that address's state at the tip, and only then does the core
// look the account up, its callback answering from what the node said. The
// core checks the answer and turns the balance into decimal wei.

/** The account state the core's `AccountLookup` callback returns. */
export type CoreAccountState = {
  /** Big-endian, at most 32 bytes. */
  balance: ArrayBuffer;
  nonce: bigint;
};

export type CoreAccountLookup = {
  accountState(address: ArrayBuffer, blockHash: ArrayBuffer): CoreAccountState;
};

type CoreRestoredAccount = {
  index: number;
  address: string;
  balance: string;
  nonce: bigint;
  used: boolean;
  unverified: boolean;
};

type CoreRestoreLookup = {
  deriveAccount(index: number): { index: number; address: string };
  lookUpAccount(index: number): CoreRestoredAccount;
  uniffiDestroy?(): void;
};

/** The part of the generated bindings this file uses. */
export type RestoreBindings = {
  RestoreLookup: new (
    words: string,
    lookup: CoreAccountLookup,
    tipHeight: bigint,
    tipHash: ArrayBuffer,
  ) => CoreRestoreLookup;
};

export type AccountAtTip = {
  index: number;
  address: string;
  /** In wei, as decimal digits. */
  balance: string;
  nonce: number;
  tipHeight: number;
  /** The node's report, not proved: Ghost's client has no state proof yet. */
  unverified: boolean;
};

export type FetchAccountState = (
  address: string,
  blockHash: string,
) => Promise<{ balance: bigint; nonce: bigint }>;

export function hexToBytes(hex: string): Uint8Array {
  const digits = hex.replace(/^0x/i, '');
  if (digits.length % 2 !== 0 || !/^[0-9a-f]*$/i.test(digits)) {
    throw new Error('not hex');
  }
  const bytes = new Uint8Array(digits.length / 2);
  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(digits.slice(2 * i, 2 * i + 2), 16);
  }
  return bytes;
}

export function bytesToHex(bytes: ArrayBuffer | Uint8Array): string {
  const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  return `0x${Array.from(view, (b) => b.toString(16).padStart(2, '0')).join('')}`;
}

function buffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

/** A non-negative amount as minimal big-endian bytes. */
export function bigintToBytes(value: bigint): Uint8Array {
  if (value < 0n) {
    throw new Error('negative amount');
  }
  let hex = value.toString(16);
  if (hex === '0') {
    return new Uint8Array(0);
  }
  if (hex.length % 2) {
    hex = `0${hex}`;
  }
  return hexToBytes(hex);
}

/** The saved-account constructor of the generated RestoreLookup. */
export type SavedRestoreBindings = {
  RestoreLookup: {
    savedAccount(lookup: CoreAccountLookup, tipHeight: bigint, tipHash: ArrayBuffer): CoreRestoreLookup;
  };
};

type OpenLookup = (lookup: CoreAccountLookup, tipHeight: bigint, tipHash: ArrayBuffer) => CoreRestoreLookup;

/** Account `index` of `words`, looked up by the core at the tip. */
export function lookUpAccountAtTip(
  bindings: RestoreBindings,
  words: string,
  index: number,
  tip: { height: number; hash: string },
  fetchState: FetchAccountState,
): Promise<AccountAtTip> {
  return lookUpWith(
    (lookup, tipHeight, tipHash) => new bindings.RestoreLookup(words, lookup, tipHeight, tipHash),
    index,
    tip,
    fetchState,
  );
}

/**
 * Account `index` of the account saved on this phone, looked up by the core
 * at the tip. The words stay in native code.
 */
export function lookUpSavedAccountAtTip(
  bindings: SavedRestoreBindings,
  index: number,
  tip: { height: number; hash: string },
  fetchState: FetchAccountState,
): Promise<AccountAtTip> {
  return lookUpWith(
    (lookup, tipHeight, tipHash) => bindings.RestoreLookup.savedAccount(lookup, tipHeight, tipHash),
    index,
    tip,
    fetchState,
  );
}

async function lookUpWith(
  open: OpenLookup,
  index: number,
  tip: { height: number; hash: string },
  fetchState: FetchAccountState,
): Promise<AccountAtTip> {
  let answer: { address: string; blockHash: string; state: CoreAccountState } | null = null;
  const lookup: CoreAccountLookup = {
    accountState(address, blockHash) {
      const asked = { address: bytesToHex(address), blockHash: bytesToHex(blockHash) };
      if (!answer || asked.address !== answer.address || asked.blockHash !== answer.blockHash) {
        throw new Error('the core asked about an account the node was not asked about');
      }
      return answer.state;
    },
  };
  const restore = open(lookup, BigInt(tip.height), buffer(hexToBytes(tip.hash)));
  try {
    const { address } = restore.deriveAccount(index);
    const blockHash = tip.hash.toLowerCase();
    const state = await fetchState(address, blockHash);
    answer = { address: address.toLowerCase(), blockHash, state: { balance: buffer(bigintToBytes(state.balance)), nonce: state.nonce } };
    const account = restore.lookUpAccount(index);
    return {
      index: account.index,
      address: account.address,
      balance: account.balance,
      nonce: Number(account.nonce),
      tipHeight: tip.height,
      unverified: account.unverified,
    };
  } finally {
    restore.uniffiDestroy?.();
  }
}
