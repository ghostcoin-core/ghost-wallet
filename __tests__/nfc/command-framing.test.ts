// The NTAG 424 DNA command framing, against NXP's published vectors (AN12196)
// and the datasheet's layouts.
import {
  ChipError,
  IntegrityError,
  accessRights,
  fileRangeHeader,
  fromHex,
  pad,
  selectNdefApplication,
  splitResponse,
  toHex,
  truncateMac,
  unpad,
  wrapNative,
} from '../../modules/ghost-nfc/apdu';
import { FACTORY_FILE_SETTINGS, KEY_FILE_SETTINGS, cardRecord, identifyCard, sealedOf } from '../../modules/ghost-nfc/card';
import { readSignature, verifyOriginality } from '../../modules/ghost-nfc/originality';
import { SecureSession, type Tag } from '../../modules/ghost-nfc/secure-messaging';
import { FakeNtag424, FakeVault, GENUINE_SIGNATURE, GENUINE_UID, ZERO_KEY, cmac, sessionKeys, sessionVector } from './fake-card';

/** A tag that answers each command with the next scripted answer and keeps what it was sent. */
function scriptedTag(answers: string[]): Tag & { sent: string[] } {
  const queue = [...answers];
  const sent: string[] = [];
  return {
    sent,
    async transceive(apdu) {
      sent.push(toHex(apdu));
      const next = queue.shift();
      if (next === undefined) throw new Error('unexpected command');
      return fromHex(next);
    },
  };
}

describe('ISO 7816-4 wrapping', () => {
  it('selects the NDEF application by name as AN12196 does', () => {
    expect(toHex(selectNdefApplication())).toBe('00A4040007D276000085010100');
  });

  it('wraps a native command without data as 90 INS 00 00 00', () => {
    expect(toHex(wrapNative(0x60))).toBe('9060000000');
  });

  it('wraps data with Lc and Le', () => {
    expect(toHex(wrapNative(0x71, Uint8Array.of(0x00, 0x00)))).toBe('9071000002000000');
  });

  it('refuses data that does not fit a short APDU', () => {
    expect(() => wrapNative(0x8d, new Uint8Array(256))).toThrow(RangeError);
  });

  it('splits the status words from the data', () => {
    expect(splitResponse(fromHex('0102039100'))).toEqual({ data: Uint8Array.of(1, 2, 3), sw1: 0x91, sw2: 0x00 });
    expect(() => splitResponse(Uint8Array.of(0x91))).toThrow(IntegrityError);
  });

  it('lays out ReadData and WriteData headers little endian', () => {
    expect(toHex(fileRangeHeader(0x02, 0x80, 0x0a))).toBe('02800000' + '0A0000');
    expect(toHex(fileRangeHeader(0x03, 0x010203, 0x00ff00))).toBe('03030201' + '00FF00');
    expect(() => fileRangeHeader(2, -1, 1)).toThrow(RangeError);
  });

  it('packs access rights as RW|Change, Read|Write', () => {
    expect(toHex(accessRights({ readWrite: 0xe, change: 0, read: 0xe, write: 0xe }))).toBe('E0EE');
    expect(toHex(FACTORY_FILE_SETTINGS)).toBe('00E0EE');
    // Full mode; key 2 reads and writes, key 0 changes the settings.
    expect(toHex(KEY_FILE_SETTINGS)).toBe('032022');
    expect(() => accessRights({ readWrite: 16, change: 0, read: 0, write: 0 })).toThrow(RangeError);
  });
});

describe('padding and MAC truncation', () => {
  it('pads with 0x80 then zeros, always adding a byte', () => {
    expect(toHex(pad(fromHex('0102030405060708090A')))).toBe('0102030405060708090A800000000000');
    expect(pad(new Uint8Array(16))).toHaveLength(32);
    expect(pad(new Uint8Array(16))[16]).toBe(0x80);
  });

  it('removes padding and refuses unpadded data', () => {
    expect(toHex(unpad(fromHex('04958CAA5C5E80800000000000000000')))).toBe('04958CAA5C5E80');
    expect(() => unpad(new Uint8Array(16))).toThrow(IntegrityError);
    expect(() => unpad(fromHex('0102030405060708090A0B0C0D0E0F10'))).toThrow(IntegrityError);
  });

  it('keeps the odd bytes of the CMAC (AN12196 5.12)', () => {
    expect(toHex(truncateMac(fromHex('426CD70CE153ED315E5B139CB97384AA')))).toBe('6C0C53315B9C73AA');
    expect(() => truncateMac(new Uint8Array(8))).toThrow(RangeError);
  });
});

describe('AuthenticateEV2First (AN12196 5.6, key 0 all zeros)', () => {
  const rndA = fromHex('13C5DB8A5930439FC3DEF9A4C675360F');
  const rndB = fromHex('B9E2FC789B64BF237CCCAA20EC7E6E48');

  it('derives the session keys of the note from SV1 and SV2', () => {
    expect(toHex(sessionVector([0xa5, 0x5a], rndA, rndB))).toBe('A55A0001008013C56268A548D8FBBF237CCCAA20EC7E6E48C3DEF9A4C675360F');
    const keys = sessionKeys(ZERO_KEY, rndA, rndB);
    expect(toHex(keys.enc)).toBe('1309C877509E5A215007FF0ED19CA564');
    expect(toHex(keys.mac)).toBe('4C6626F5E72EA694202139295C7A7FC7');
  });

  it('sends the note\'s frames, takes its TI and then encrypts WriteData as in AN12196 5.8.2', async () => {
    const vault = new FakeVault();
    vault.random = () => rndA;
    const ndefPadded = fromHex(
      '0051D1014D550463686F6F73652E75726C2E636F6D2F6E7461673432343F653D303030303030303030303030303030303030303030303030303030303030303026633D3030303030303030303030303030303000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000',
    );
    const ndef = unpad(ndefPadded);
    const macKey = fromHex('4C6626F5E72EA694202139295C7A7FC7');
    const ti = fromHex('9D00C4DF');
    const answerMac = truncateMac(cmac(macKey, Uint8Array.of(0x00, 0x01, 0x00, ...ti)));
    const tag = scriptedTag([
      'A04C124213C186F22399D33AC2A30215' + '91AF',
      '3FA64DB5446D1F34CD6EA311167F5E4985B89690C04A05F17FA7AB2F08120663' + '9100',
      toHex(answerMac) + '9100',
    ]);

    const session = await SecureSession.authenticate(tag, vault, toHex(GENUINE_UID), { set: 'factory', keyNo: 0 });
    expect(tag.sent[0]).toBe('9071000002000000');
    expect(tag.sent[1]).toBe(
      '90AF000020' + '35C3E05A752E0144BAC0DE51C1F22C56B34408A23D8AEA266CAB947EA8E0118D' + '00',
    );
    expect(toHex(session.ti)).toBe('9D00C4DF');
    expect(session.counter).toBe(0);

    await session.full({ command: 0x8d, header: fileRangeHeader(0x02, 0, ndef.length), plaintext: { padded: pad(ndef) } });
    const write = tag.sent[2];
    expect(write.slice(0, 8)).toBe('908D0000');
    expect(write.slice(10, 24)).toBe(toHex(fileRangeHeader(0x02, 0, ndef.length)));
    expect(write.slice(24, 24 + 2 * ndefPadded.length)).toBe(
      '421C73A27D827658AF481FDFF20A5025B559D0E3AA21E58D347F343CFFC768BFE596C706BC00F2176781D4B0242642A0FF5A42C461AAF894D9A1284B8C76BCFA658ACD40555D362E08DB15CF421B51283F9064BCBE20E96CAE545B407C9D651A3315B27373772E5DA2367D2064AE054AF996C6F1F669170FA88CE8C4E3A4A7BBBEF0FD971FF532C3A802AF745660F2B4',
    );
    expect(session.counter).toBe(1);
  });

  it('turns a refused key into an authentication error', async () => {
    const tag = scriptedTag(['A04C124213C186F22399D33AC2A30215' + '91AF', '91AE']);
    const attempt = SecureSession.authenticate(tag, new FakeVault(), '04518DFAA96180', { set: 'factory', keyNo: 0 });
    await expect(attempt).rejects.toThrow(ChipError);
    await expect(
      SecureSession.authenticate(scriptedTag(['A04C124213C186F22399D33AC2A30215' + '91AF', '91AE']), new FakeVault(), 'X', {
        set: 'factory',
        keyNo: 0,
      }).catch((error: ChipError) => error.authentication),
    ).resolves.toBe(true);
  });
});

/** A session on preset keys and TI, after a scripted key exchange. */
async function presetSession(keys: { enc: string; mac: string; ti: string }, answers: string[]) {
  const vault = new FakeVault({ enc: fromHex(keys.enc), mac: fromHex(keys.mac), ti: fromHex(keys.ti) });
  const tag = scriptedTag(['00'.repeat(16) + '91AF', '00'.repeat(32) + '9100', ...answers]);
  const session = await SecureSession.authenticate(tag, vault, 'card', { set: 'factory', keyNo: 0 });
  return { session, tag };
}

describe('secure messaging in CommMode.Full', () => {
  const writeKeys = { enc: '7A93D6571E4B180FCA6AC90C9A7488D4', mac: 'FC4AF159B62E549B5812394CAB1918CC', ti: '7614281A' };

  it('frames WriteData of AN12196 5.12: IV, ciphertext, MAC and the answer\'s MAC', async () => {
    const { session, tag } = await presetSession(writeKeys, ['C26D236E4A7C046D' + '9100']);
    expect(toHex(session.ivInput('command'))).toBe('A55A7614281A00000000000000000000');
    const header = fileRangeHeader(0x03, 0, 10);
    const input = session.commandMacInput(0x8d, header, fromHex('6B5E6804909962FC4E3FF5522CF0F843'));
    expect(toHex(input)).toBe('8D00007614281A030000000A00006B5E6804909962FC4E3FF5522CF0F843');

    await session.full({ command: 0x8d, header, plaintext: { padded: pad(fromHex('0102030405060708090A')) } });
    expect(tag.sent[2]).toBe('908D00001F' + '030000000A0000' + '6B5E6804909962FC4E3FF5522CF0F843' + '6C0C53315B9C73AA' + '00');
    expect(session.counter).toBe(1);
    expect(toHex(session.responseMacInput(0x00, new Uint8Array(0)))).toBe('0001007614281A');
  });

  it('refuses an answer whose MAC is wrong', async () => {
    const { session } = await presetSession(writeKeys, ['C26D236E4A7C046E' + '9100']);
    await expect(
      session.full({ command: 0x8d, header: fileRangeHeader(0x03, 0, 10), plaintext: { padded: pad(fromHex('0102030405060708090A')) } }),
    ).rejects.toThrow(IntegrityError);
  });

  it('refuses an answer without a MAC', async () => {
    const { session } = await presetSession(writeKeys, ['9100']);
    await expect(session.full({ command: 0x5f, header: Uint8Array.of(2), plaintext: { padded: pad(KEY_FILE_SETTINGS) } })).rejects.toThrow(
      IntegrityError,
    );
  });

  it('decrypts an answer with the response IV of the next counter (AN12196 5.20)', async () => {
    const keys = { enc: '2B4D963C014DC36F24F69A50A394F875', mac: '379D32130CE61705DD5FD8C36B95D764', ti: 'DF055522' };
    const { session, tag } = await presetSession(keys, ['70756055688505B52A5E26E59E329CD6' + '595F672298EA41B7' + '9100']);
    const uid = await session.full({ command: 0x51, header: new Uint8Array(0), decrypt: true });
    expect(tag.sent[2]).toBe('9051000008' + '8E2C155ADDA99BE3' + '00');
    expect(toHex(uid)).toBe('04958CAA5C5E80');
    expect(toHex(session.ivInput('response'))).toBe('5AA5DF0555220100' + '0000000000000000');
  });

  it('stops the session when the chip refuses a command', async () => {
    const { session } = await presetSession(writeKeys, ['919D']);
    await expect(session.full({ command: 0x5f, header: Uint8Array.of(2), plaintext: { padded: pad(KEY_FILE_SETTINGS) } })).rejects.toThrow(
      ChipError,
    );
    await expect(session.full({ command: 0x5f, header: Uint8Array.of(2) })).rejects.toThrow('closed');
  });

  it('takes no MAC back when the session key itself was changed', async () => {
    const { session, tag } = await presetSession(writeKeys, ['9100']);
    await expect(
      session.full({
        command: 0xc4,
        header: Uint8Array.of(0),
        plaintext: { changeKey: { keyNo: 0, to: 'factory', from: 'factory', version: 0 } },
        responseMac: false,
      }),
    ).resolves.toHaveLength(0);
    // NewKey || KeyVer, padded: two blocks, then the MAC.
    expect(tag.sent[2].slice(0, 12)).toBe('90C400002900');
  });
});

describe('the NXP originality signature (AN12196 table 30)', () => {
  it('accepts NXP\'s signature over the UID', () => {
    expect(verifyOriginality(GENUINE_UID, GENUINE_SIGNATURE)).toBe(true);
  });

  it('refuses a changed signature or another UID', () => {
    const signature = GENUINE_SIGNATURE.slice();
    signature[0] ^= 0x01;
    expect(verifyOriginality(GENUINE_UID, signature)).toBe(false);
    const uid = GENUINE_UID.slice();
    uid[6] ^= 0x01;
    expect(verifyOriginality(uid, GENUINE_SIGNATURE)).toBe(false);
    expect(verifyOriginality(GENUINE_UID, GENUINE_SIGNATURE.slice(0, 55))).toBe(false);
    expect(verifyOriginality(GENUINE_UID, new Uint8Array(56))).toBe(false);
  });

  it('reads the signature with Read_Sig in plain, also when the chip answers 91 90', async () => {
    const tag = scriptedTag([toHex(GENUINE_SIGNATURE) + '9190']);
    expect(await readSignature(tag)).toEqual(GENUINE_SIGNATURE);
    expect(tag.sent).toEqual(['903C0000010000']);
  });
});

describe('GetVersion', () => {
  it('reads the UID of an NTAG 424 DNA from the third frame', async () => {
    const card = await identifyCard(new FakeNtag424());
    expect(card.uidHex).toBe('04518DFAA96180');
  });

  it('refuses a chip that is not an NXP NTAG', async () => {
    const tag = scriptedTag(['9000', '04010101001805' + '91AF', '04010101041805' + '91AF', '04518DFAA96180CF39A1494004229100']);
    await expect(identifyCard(tag)).rejects.toThrow('not an NTAG 424 DNA');
  });
});

describe('the card record', () => {
  it('carries a header and the sealed key, and refuses what does not fit the file', () => {
    const sealed = Uint8Array.from({ length: 40 }, (_, i) => i);
    const record = cardRecord(sealed);
    expect(toHex(record.slice(0, 5))).toBe('474B010028');
    expect(sealedOf(record)).toEqual(sealed);
    expect(sealedOf(new Uint8Array(256))).toBeNull();
    expect(() => cardRecord(new Uint8Array(252))).toThrow('does not fit');
  });
});
