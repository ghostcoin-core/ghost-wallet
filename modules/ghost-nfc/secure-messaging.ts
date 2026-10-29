// AuthenticateEV2First and EV2 secure messaging (CommMode.Full), as framed by
// the NTAG 424 DNA datasheet and AN12196.
//
// The keys never come here. The native vault (ios/CardVault.swift) holds the
// card's keys and the session keys, and does every AES and CMAC operation
// with them; this file builds the bytes those operations run over and checks
// what comes back:
//
// - the command MAC input: Cmd || CmdCtr || TI || CmdHeader || EncData;
// - the response MAC input: RC || CmdCtr + 1 || TI || RespData;
// - the IV inputs: A5 5A || TI || CmdCtr || 0^8 (command), 5A A5 || TI || CmdCtr + 1 || 0^8 (response);
// - the 8-byte MAC: the CMAC's odd bytes (truncateMac);
// - CmdCtr, little endian, one more after every command and response.
import {
  COMMAND,
  IntegrityError,
  STATUS,
  concat,
  equalBytes,
  expectNative,
  le16,
  splitResponse,
  truncateMac,
  unpad,
  wrapNative,
} from './apdu';

/** Something that sends one APDU to the card and returns its raw answer. */
export type Tag = {
  transceive(apdu: Uint8Array): Promise<Uint8Array>;
};

/** Which key: the chip's factory key (all zeros), or this card's own keys saved in this phone's Keychain. */
export type KeySet = 'factory' | 'saved';

export type KeyRef = { set: KeySet; keyNo: number };

/**
 * What the vault encrypts. `padded` is public data, already padded. A
 * `changeKey` cryptogram is built in the vault, because it holds keys:
 * NewKey || KeyVer for the key the session is authenticated with, else
 * (NewKey XOR OldKey) || KeyVer || CRC32(NewKey), then padded.
 */
export type VaultPlaintext =
  | { padded: Uint8Array }
  | { changeKey: { keyNo: number; to: KeySet; from: KeySet; version: number } };

/**
 * The native side that holds secrets. Card UIDs are hex, upper case. Nothing
 * it returns is a key: the encrypted RndA || RndB', the TI, CMACs of bytes
 * this side chose, ciphertexts and decrypted card data.
 */
export type CardVault = {
  /** Decrypts E(K, RndB) with `key` of card `uid`, draws RndA and returns E(K, RndA || RndB <<< 8). */
  authPart2(uid: string, key: KeyRef, encryptedRndB: Uint8Array): Uint8Array;
  /** Checks the chip's RndA', derives the session keys and returns the 4-byte TI. Throws when RndA' is wrong. */
  authFinish(encryptedResponse: Uint8Array): Uint8Array;
  /** The 16-byte CMAC of `input` under the session's MAC key. */
  cmac(input: Uint8Array): Uint8Array;
  /** AES-CBC under the session's ENC key, with IV = E(SesAuthENCKey, ivInput). */
  encrypt(ivInput: Uint8Array, plaintext: VaultPlaintext): Uint8Array;
  /** The reverse of `encrypt` for public card data; padding is left on. */
  decrypt(ivInput: Uint8Array, ciphertext: Uint8Array): Uint8Array;
  /** Wipes the session keys. */
  endSession(): void;
};

const MAC_BYTES = 8;

/** What a command sends and how its answer comes back. */
export type FullCommand = {
  command: number;
  header: Uint8Array;
  plaintext?: VaultPlaintext;
  /** The answer carries a MAC (false only when the authenticated key itself was changed). */
  responseMac?: boolean;
  /** The answer's data is encrypted. */
  decrypt?: boolean;
};

/** One authenticated session with the card. */
export class SecureSession {
  private commandCounter = 0;
  private open = true;

  private constructor(
    private readonly tag: Tag,
    private readonly vault: CardVault,
    readonly ti: Uint8Array,
  ) {}

  /** AuthenticateEV2First with `key`, then the session it opens. */
  static async authenticate(tag: Tag, vault: CardVault, uid: string, key: KeyRef): Promise<SecureSession> {
    const first = splitResponse(await tag.transceive(wrapNative(COMMAND.authenticateEV2First, Uint8Array.of(key.keyNo, 0x00))));
    const encryptedRndB = expectNative('AuthenticateEV2First', first, [STATUS.more]);
    if (encryptedRndB.length !== 16) {
      throw new IntegrityError('AuthenticateEV2First sent a wrong-sized challenge');
    }
    const part2 = vault.authPart2(uid, key, encryptedRndB);
    const second = splitResponse(await tag.transceive(wrapNative(COMMAND.additionalFrame, part2)));
    const encryptedResponse = expectNative('AuthenticateEV2First', second);
    if (encryptedResponse.length !== 32) {
      throw new IntegrityError('AuthenticateEV2First sent a wrong-sized answer');
    }
    const ti = vault.authFinish(encryptedResponse);
    if (ti.length !== 4) {
      throw new IntegrityError('the transaction identifier is 4 bytes');
    }
    return new SecureSession(tag, vault, ti);
  }

  get counter(): number {
    return this.commandCounter;
  }

  /** A5 5A || TI || CmdCtr || 0^8 for a command; 5A A5 || ... for a response. */
  ivInput(direction: 'command' | 'response'): Uint8Array {
    const label = direction === 'command' ? [0xa5, 0x5a] : [0x5a, 0xa5];
    return concat(label, this.ti, le16(this.commandCounter), new Uint8Array(8));
  }

  /** Cmd || CmdCtr || TI || CmdHeader || EncData, the command's MAC input. */
  commandMacInput(command: number, header: Uint8Array, encrypted: Uint8Array): Uint8Array {
    return concat([command], le16(this.commandCounter), this.ti, header, encrypted);
  }

  /** RC || CmdCtr || TI || RespData, the response's MAC input (after the counter moved on). */
  responseMacInput(status: number, data: Uint8Array): Uint8Array {
    return concat([status], le16(this.commandCounter), this.ti, data);
  }

  /** Sends one command in CommMode.Full and returns its answer's (decrypted) data. */
  async full({ command, header, plaintext, responseMac = true, decrypt = false }: FullCommand): Promise<Uint8Array> {
    if (!this.open) {
      throw new Error('the card session is closed');
    }
    const encrypted = plaintext ? this.vault.encrypt(this.ivInput('command'), plaintext) : new Uint8Array(0);
    const mac = truncateMac(this.vault.cmac(this.commandMacInput(command, header, encrypted)));
    const response = splitResponse(await this.tag.transceive(wrapNative(command, concat(header, encrypted, mac))));
    let data: Uint8Array;
    try {
      data = expectNative(commandName(command), response);
    } catch (error) {
      // A refused command ends the chip's authentication.
      this.close();
      throw error;
    }
    this.commandCounter += 1;
    if (!responseMac) {
      this.close();
      return data;
    }
    if (data.length < MAC_BYTES) {
      this.close();
      throw new IntegrityError(`${commandName(command)} answered without a MAC`);
    }
    const body = data.slice(0, data.length - MAC_BYTES);
    const expected = truncateMac(this.vault.cmac(this.responseMacInput(response.sw2, body)));
    if (!equalBytes(expected, data.slice(data.length - MAC_BYTES))) {
      this.close();
      throw new IntegrityError(`${commandName(command)} answered with a wrong MAC`);
    }
    if (!decrypt || body.length === 0) {
      return body;
    }
    if (body.length % 16 !== 0) {
      this.close();
      throw new IntegrityError(`${commandName(command)} answered with a broken block`);
    }
    return unpad(this.vault.decrypt(this.ivInput('response'), body));
  }

  /** Wipes the session keys in the vault. */
  close(): void {
    if (this.open) {
      this.open = false;
      this.vault.endSession();
    }
  }
}

function commandName(command: number): string {
  const entry = Object.entries(COMMAND).find(([, code]) => code === command);
  return entry ? entry[0] : `command ${command}`;
}
