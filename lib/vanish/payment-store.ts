// Where the step sequence saves Vanish, Summon and Claim payments: files in
// the app's Documents folder, excluded from nothing but holding only public
// data. A record is the payment intent (the commit data or the reveal's
// marker and terms) and its steps; a payload is a signed transaction, public
// once sent. No Phantom Key and no account word is ever in either.
//
// The core's store callbacks are synchronous and must be durable when they
// return, so the files are written with the synchronous file API, each one
// whole: written under a temporary name, then moved over the old one.
import type { CorePaymentRecord, CorePaymentStore, VanishBindings } from '../../modules/ghost-core';
import { bytesToHex } from '../../modules/ghost-core/account-lookup';

/** A folder of small binary files. */
export type PaymentFiles = {
  read(name: string): Uint8Array | null;
  /** Replaces the file whole. */
  write(name: string, bytes: Uint8Array): void;
  remove(name: string): void;
  list(): string[];
};

const RECORD = '.record';
const PAYLOAD = '.tx';
const REFUSED = '.refused';

/**
 * The Vanishes the node refused for lack of funds. The core checksums a record
 * with its details, so this is kept beside it: a small file holding why,
 * removed with the record. No marker reads as not refused.
 */
export type RefusedMarks = {
  markRefused(id: string, reason: string): void;
  /** Why payment `id` was refused, or null when it was not. */
  refusedReason(id: string): string | null;
};

export type PaymentStore = CorePaymentStore & RefusedMarks;

/** The refused marks of `store`, or null when it keeps none (then nothing is kept across restarts). */
export function refusedMarks(store: CorePaymentStore | null | undefined): RefusedMarks | null {
  const marks = store as Partial<RefusedMarks> | null | undefined;
  return marks && typeof marks.markRefused === 'function' && typeof marks.refusedReason === 'function'
    ? (marks as RefusedMarks)
    : null;
}

function safeId(id: string): string {
  if (!/^[a-z0-9-]{1,64}$/.test(id)) {
    throw new Error('a payment id is letters, digits and hyphens only');
  }
  return id;
}

function view(bytes: ArrayBuffer | Uint8Array): Uint8Array {
  return bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
}

function buffer(bytes: Uint8Array): ArrayBuffer {
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength) as ArrayBuffer;
}

function payloadName(id: string, transactionHash: ArrayBuffer): string {
  return `${safeId(id)}-${bytesToHex(transactionHash).slice(2)}${PAYLOAD}`;
}

/** The core's `PaymentStore` over `files`. */
export function paymentStore(
  core: Pick<VanishBindings, 'encodePaymentRecord' | 'decodePaymentRecord'>,
  files: PaymentFiles,
): PaymentStore {
  return {
    save(record: CorePaymentRecord) {
      files.write(`${safeId(record.id)}${RECORD}`, view(core.encodePaymentRecord(record)));
    },
    load(id: string) {
      const bytes = files.read(`${safeId(id)}${RECORD}`);
      // A record that does not decode throws: the core shows it, never resends.
      return bytes ? core.decodePaymentRecord(buffer(bytes)) : undefined;
    },
    list() {
      return files
        .list()
        .filter((name) => name.endsWith(RECORD))
        .map((name) => name.slice(0, -RECORD.length));
    },
    remove(id: string) {
      const prefix = `${safeId(id)}-`;
      for (const name of files.list()) {
        if (name.startsWith(prefix) && name.endsWith(PAYLOAD)) {
          files.remove(name);
        }
      }
      files.remove(`${id}${RECORD}`);
      files.remove(`${id}${REFUSED}`);
    },
    markRefused(id: string, reason: string) {
      files.write(`${safeId(id)}${REFUSED}`, new TextEncoder().encode(reason));
    },
    refusedReason(id: string) {
      const bytes = files.read(`${safeId(id)}${REFUSED}`);
      if (!bytes) {
        return null;
      }
      try {
        return new TextDecoder().decode(bytes);
      } catch {
        // Unreadable still means refused: it is never sent.
        return '';
      }
    },
    savePayload(id: string, transactionHash: ArrayBuffer, signedTransaction: ArrayBuffer) {
      files.write(payloadName(id, transactionHash), view(signedTransaction));
    },
    loadPayload(id: string, transactionHash: ArrayBuffer) {
      const bytes = files.read(payloadName(id, transactionHash));
      return bytes ? buffer(bytes) : undefined;
    },
  };
}

type FileSystem = typeof import('expo-file-system');

/** The `payments` folder in Documents; null in a build without the module. */
export function documentPaymentFiles(): PaymentFiles | null {
  let fs: FileSystem;
  try {
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    fs = require('expo-file-system') as FileSystem;
  } catch {
    return null;
  }
  const folder = new fs.Directory(fs.Paths.document, 'payments');
  const ensure = () => {
    if (!folder.exists) {
      folder.create({ intermediates: true });
    }
  };
  return {
    read(name) {
      const file = new fs.File(folder, name);
      return file.exists ? file.bytesSync() : null;
    },
    write(name, bytes) {
      ensure();
      const temporary = new fs.File(folder, `${name}.new`);
      if (temporary.exists) {
        temporary.delete();
      }
      temporary.create();
      temporary.writeSync(bytes);
      const target = new fs.File(folder, name);
      if (target.exists) {
        target.delete();
      }
      temporary.moveSync(target);
    },
    remove(name) {
      const file = new fs.File(folder, name);
      if (file.exists) {
        file.delete();
      }
    },
    list() {
      if (!folder.exists) {
        return [];
      }
      return folder
        .list()
        .map((entry) => entry.name)
        .filter((name) => !name.endsWith('.new'));
    },
  };
}
