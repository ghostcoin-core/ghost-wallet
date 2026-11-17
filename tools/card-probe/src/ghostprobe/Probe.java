package ghostprobe;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.apdu.ExtendedLength;
import javacardx.crypto.Cipher;

/**
 * Throwaway measurement applet. It reports which algorithms the card offers,
 * its free memory, and times bytecode Keccak-f[1600], ChaCha20-Poly1305 and
 * LMS (SHA-256, H10/W4) work. It holds no real secret and is never shipped.
 */
public class Probe extends Applet implements ExtendedLength {

    private static final byte INS_NOP = (byte) 0x00;
    private static final byte INS_INFO = (byte) 0x01;
    private static final byte INS_ALLOC_TREE = (byte) 0x02;
    private static final byte INS_SHA256_LOOP = (byte) 0x10;
    private static final byte INS_KECCAK_S_LOOP = (byte) 0x20;
    private static final byte INS_SHA3_S = (byte) 0x22;
    private static final byte INS_AEAD = (byte) 0x30;
    private static final byte INS_LMS_SIGN = (byte) 0x40;
    private static final byte INS_LMS_LEAF = (byte) 0x41;
    private static final byte INS_EXT = (byte) 0x50;

    // ---- Keccak tables ----
    private static final byte[] ROT = {0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14};
    private static final byte[] PI = {0, 10, 20, 5, 15, 16, 1, 11, 21, 6, 7, 17, 2, 12, 22, 23, 8, 18, 3, 13, 14, 24, 9, 19, 4};
    private static final short[] LM = {0, 1, 3, 7, 15, 31, 63, 127, 255, 511, 1023, 2047, 4095, 8191, 16383, 32767};
    private static final short[] RCS = {
        (short)0x0001,(short)0x0000,(short)0x0000,(short)0x0000,(short)0x8082,(short)0x0000,(short)0x0000,(short)0x0000,
        (short)0x808A,(short)0x0000,(short)0x0000,(short)0x8000,(short)0x8000,(short)0x8000,(short)0x0000,(short)0x8000,
        (short)0x808B,(short)0x0000,(short)0x0000,(short)0x0000,(short)0x0001,(short)0x8000,(short)0x0000,(short)0x0000,
        (short)0x8081,(short)0x8000,(short)0x0000,(short)0x8000,(short)0x8009,(short)0x0000,(short)0x0000,(short)0x8000,
        (short)0x008A,(short)0x0000,(short)0x0000,(short)0x0000,(short)0x0088,(short)0x0000,(short)0x0000,(short)0x0000,
        (short)0x8009,(short)0x8000,(short)0x0000,(short)0x0000,(short)0x000A,(short)0x8000,(short)0x0000,(short)0x0000,
        (short)0x808B,(short)0x8000,(short)0x0000,(short)0x0000,(short)0x008B,(short)0x0000,(short)0x0000,(short)0x8000,
        (short)0x8089,(short)0x0000,(short)0x0000,(short)0x8000,(short)0x8003,(short)0x0000,(short)0x0000,(short)0x8000,
        (short)0x8002,(short)0x0000,(short)0x0000,(short)0x8000,(short)0x0080,(short)0x0000,(short)0x0000,(short)0x8000,
        (short)0x800A,(short)0x0000,(short)0x0000,(short)0x0000,(short)0x000A,(short)0x8000,(short)0x0000,(short)0x8000,
        (short)0x8081,(short)0x8000,(short)0x0000,(short)0x8000,(short)0x8080,(short)0x0000,(short)0x0000,(short)0x8000,
        (short)0x0001,(short)0x8000,(short)0x0000,(short)0x0000,(short)0x8008,(short)0x8000,(short)0x0000,(short)0x8000};

    // Keccak state, 16-bit limbs: A[4*lane + k], k = 0 is the low 16 bits.
    private short[] ks;
    private short[] kt;   // 0..19 column parities, 20..119 rho/pi output
    // Poly1305 limbs in RAM: h 0..16, r 17..33, c 34..50, x low 51..67,
    // s 68..83, x high 85..101 (the card has no RAM int arrays)
    private short[] ph;
    private byte[] mac;   // 48 aad block + 352 ciphertext + 16 lengths = 416
    private byte[] blk;   // 64-byte keystream block

    // LMS
    private MessageDigest sha;
    private MessageDigest shaK;
    private RandomData rng;
    private byte[] lb;    // I(16) q(4) i(2) j(1) tmp(32) = 55
    private byte[] lh;    // 32-byte hash out, 32-byte Q, 32-byte C
    private byte[] seed;  // persistent 32
    private byte[] leafIx; // persistent 4
    private byte[] tree0;
    private byte[] tree1;
    private short[] mem;

    private Probe() {
        ks = JCSystem.makeTransientShortArray((short) 100, JCSystem.CLEAR_ON_DESELECT);
        kt = JCSystem.makeTransientShortArray((short) 120, JCSystem.CLEAR_ON_DESELECT);
        ph = JCSystem.makeTransientShortArray((short) 102, JCSystem.CLEAR_ON_DESELECT);
        mac = JCSystem.makeTransientByteArray((short) 416, JCSystem.CLEAR_ON_DESELECT);
        blk = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        lb = JCSystem.makeTransientByteArray((short) 55, JCSystem.CLEAR_ON_DESELECT);
        lh = JCSystem.makeTransientByteArray((short) 96, JCSystem.CLEAR_ON_DESELECT);
        mem = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_DESELECT);
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        shaK = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        rng = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        seed = new byte[32];
        leafIx = new byte[4];
        rng.generateData(seed, (short) 0, (short) 32);
    }

    public static void install(byte[] b, short off, byte len) {
        new Probe().register(b, (short) (off + 1), b[off]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != (byte) 0x80) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        short n = Util.getShort(buf, ISO7816.OFFSET_P1);
        short out = 0;
        short i;
        switch (buf[ISO7816.OFFSET_INS]) {
        case INS_NOP:
            break;
        case INS_INFO:
            out = info(buf);
            break;
        case INS_ALLOC_TREE:
            if (tree0 == null) {
                tree0 = new byte[32752];
                tree1 = new byte[32752];
            }
            out = memInfo(buf, (short) 0);
            break;
        case INS_SHA256_LOOP:
            for (i = 0; i < n; i++) {
                sha.doFinal(lb, (short) 0, (short) 55, lh, (short) 0);
            }
            break;
        case INS_KECCAK_S_LOOP:
            for (i = 0; i < n; i++) {
                keccakS();
            }
            break;
        case INS_SHA3_S: {
            short len = apdu.setIncomingAndReceive();
            out = sha3(buf, apdu.getOffsetCdata(), len);
            break;
        }
        case INS_AEAD:
            for (i = 0; i < n; i++) {
                aead();
            }
            Util.arrayCopyNonAtomic(mac, (short) 48, buf, (short) 0, (short) 16);
            Util.arrayCopyNonAtomic(blk, (short) 0, buf, (short) 16, (short) 16);
            out = 32;
            break;
        case INS_LMS_SIGN: {
            int total = 0;
            for (i = 0; i < n; i++) {
                total += lmsSign();
            }
            setInt(buf, (short) 0, total);
            out = 4;
            break;
        }
        case INS_LMS_LEAF: {
            int total = 0;
            for (i = 0; i < n; i++) {
                total += lmsLeaf(i);
            }
            setInt(buf, (short) 0, total);
            Util.arrayCopyNonAtomic(lh, (short) 0, buf, (short) 4, (short) 32);
            out = 36;
            break;
        }
        case INS_EXT:
            ext(apdu);
            return;
        default:
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
        if (out > 0) {
            apdu.setOutgoingAndSend((short) 0, out);
        }
    }

    // ---------------- info ----------------

    private short info(byte[] buf) {
        short o = 0;
        buf[o++] = md(MessageDigest.ALG_SHA_256);
        buf[o++] = md(MessageDigest.ALG_SHA_512);
        buf[o++] = md(MessageDigest.ALG_SHA3_256);
        buf[o++] = md(MessageDigest.ALG_SHA3_512);
        buf[o++] = ci(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD);
        buf[o++] = ci(Cipher.ALG_AES_CTR);
        buf[o++] = ci((byte) 30); // AEADCipher.ALG_AES_GCM
        buf[o++] = ci((byte) 19); // AEADCipher.ALG_AES_CCM
        buf[o++] = aes256();
        buf[o++] = sg(Signature.ALG_AES_CMAC_128);
        buf[o++] = sg(Signature.ALG_HMAC_SHA_256);
        buf[o++] = rd(RandomData.ALG_SECURE_RANDOM);
        buf[o++] = rd(RandomData.ALG_TRNG);
        buf[o++] = rd(RandomData.ALG_KEYGENERATION);
        buf[o++] = 0; // RAM int arrays: not offered by this card
        o = memInfo(buf, o);
        return o;
    }

    private short memInfo(byte[] buf, short o) {
        JCSystem.getAvailableMemory(mem, (short) 0, JCSystem.MEMORY_TYPE_PERSISTENT);
        o = Util.setShort(buf, o, mem[0]);
        o = Util.setShort(buf, o, mem[1]);
        JCSystem.getAvailableMemory(mem, (short) 0, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
        o = Util.setShort(buf, o, mem[0]);
        o = Util.setShort(buf, o, mem[1]);
        JCSystem.getAvailableMemory(mem, (short) 0, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
        o = Util.setShort(buf, o, mem[0]);
        o = Util.setShort(buf, o, mem[1]);
        return o;
    }

    private static byte md(byte a) {
        try {
            MessageDigest.getInstance(a, false);
            return 1;
        } catch (CryptoException e) {
            return 0;
        } catch (Exception e) {
            return 2;
        }
    }

    private static byte ci(byte a) {
        try {
            Cipher.getInstance(a, false);
            return 1;
        } catch (CryptoException e) {
            return 0;
        } catch (Exception e) {
            return 2;
        }
    }

    private static byte sg(byte a) {
        try {
            Signature.getInstance(a, false);
            return 1;
        } catch (CryptoException e) {
            return 0;
        } catch (Exception e) {
            return 2;
        }
    }

    private static byte rd(byte a) {
        try {
            RandomData.getInstance(a);
            return 1;
        } catch (CryptoException e) {
            return 0;
        } catch (Exception e) {
            return 2;
        }
    }

    private static byte aes256() {
        try {
            KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            return 1;
        } catch (CryptoException e) {
            return 0;
        } catch (Exception e) {
            return 2;
        }
    }

    // ---------------- Keccak-f[1600], 16-bit limbs ----------------

    private void keccakS() {
        short[] a = ks;
        short[] t = kt;
        short x, y, k, b, s, q, d, r;
        for (r = 0; r < 24; r++) {
            // theta: column parities
            for (x = 0; x < 20; x++) {
                t[x] = (short) (a[x] ^ a[(short) (x + 20)] ^ a[(short) (x + 40)] ^ a[(short) (x + 60)] ^ a[(short) (x + 80)]);
            }
            for (x = 0; x < 5; x++) {
                short p = (short) (((short) (x + 4) % 5) * 4);
                short nx = (short) (((short) (x + 1) % 5) * 4);
                short n0 = t[nx], n1 = t[(short) (nx + 1)], n2 = t[(short) (nx + 2)], n3 = t[(short) (nx + 3)];
                short d0 = (short) (t[p] ^ (short) (n0 << 1) ^ (short) ((n3 >> 15) & 1));
                short d1 = (short) (t[(short) (p + 1)] ^ (short) (n1 << 1) ^ (short) ((n0 >> 15) & 1));
                short d2 = (short) (t[(short) (p + 2)] ^ (short) (n2 << 1) ^ (short) ((n1 >> 15) & 1));
                short d3 = (short) (t[(short) (p + 3)] ^ (short) (n3 << 1) ^ (short) ((n2 >> 15) & 1));
                for (y = (short) (x * 4); y < 100; y += 20) {
                    a[y] ^= d0;
                    a[(short) (y + 1)] ^= d1;
                    a[(short) (y + 2)] ^= d2;
                    a[(short) (y + 3)] ^= d3;
                }
            }
            // rho and pi into t[20..119]
            for (x = 0; x < 25; x++) {
                s = ROT[x];
                q = (short) (s >> 4);
                s = (short) (s & 15);
                b = (short) (x * 4);
                d = (short) (PI[x] * 4 + 20);
                if (s == 0) {
                    for (k = 0; k < 4; k++) {
                        t[(short) (d + k)] = a[(short) (b + ((short) (k - q) & 3))];
                    }
                } else {
                    short m = LM[s];
                    short rs = (short) (16 - s);
                    for (k = 0; k < 4; k++) {
                        t[(short) (d + k)] = (short) ((short) (a[(short) (b + ((short) (k - q) & 3))] << s)
                                | (short) ((short) (a[(short) (b + ((short) (k - q - 1) & 3))] >> rs) & m));
                    }
                }
            }
            // chi
            for (y = 0; y < 100; y += 20) {
                for (x = 0; x < 20; x += 4) {
                    short x1 = (short) (y + 20 + ((short) (x + 4) % 20));
                    short x2 = (short) (y + 20 + ((short) (x + 8) % 20));
                    short x0 = (short) (y + 20 + x);
                    for (k = 0; k < 4; k++) {
                        a[(short) (y + x + k)] = (short) (t[(short) (x0 + k)] ^ (short) (~t[(short) (x1 + k)] & t[(short) (x2 + k)]));
                    }
                }
            }
            // iota
            b = (short) (r * 4);
            a[0] ^= RCS[b];
            a[1] ^= RCS[(short) (b + 1)];
            a[2] ^= RCS[(short) (b + 2)];
            a[3] ^= RCS[(short) (b + 3)];
        }
    }

    /** SHA3-256 of a single-block message (at most 135 bytes), written to buf[0..31]. */
    private short sha3(byte[] buf, short off, short len) {
        if (len > 135) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }
        short j;
        Util.arrayFillNonAtomic(mac, (short) 0, (short) 136, (byte) 0);
        Util.arrayCopyNonAtomic(buf, off, mac, (short) 0, len);
        mac[len] ^= (byte) 0x06;
        mac[135] ^= (byte) 0x80;
        for (j = 0; j < 100; j++) {
            ks[j] = 0;
        }
        for (j = 0; j < 68; j++) {
            short o = (short) (j * 2);
            ks[j] ^= (short) ((mac[o] & 0xFF) | ((mac[(short) (o + 1)] & 0xFF) << 8));
        }
        keccakS();
        for (j = 0; j < 16; j++) {
            short o = (short) (j * 2);
            buf[o] = (byte) ks[j];
            buf[(short) (o + 1)] = (byte) (ks[j] >> 8);
        }
        return 32;
    }

    // ---------------- ChaCha20-Poly1305 (RFC 8439) ----------------

    private static int rotl(int v, short n) {
        return (v << n) | (v >>> (32 - n));
    }

    private static void put32(byte[] b, short o, int v) {
        b[o] = (byte) v;
        b[(short) (o + 1)] = (byte) (v >>> 8);
        b[(short) (o + 2)] = (byte) (v >>> 16);
        b[(short) (o + 3)] = (byte) (v >>> 24);
    }

    /** One ChaCha20 block for the given counter into blk. Key bytes are 0..31, nonce bytes 0..11. */
    private void chachaBlock(int counter) {
        final int k0 = 0x03020100, k1 = 0x07060504, k2 = 0x0b0a0908, k3 = 0x0f0e0d0c;
        final int k4 = 0x13121110, k5 = 0x17161514, k6 = 0x1b1a1918, k7 = 0x1f1e1d1c;
        final int n0 = 0x03020100, n1 = 0x07060504, n2 = 0x0b0a0908;
        int x0 = 0x61707865, x1 = 0x3320646e, x2 = 0x79622d32, x3 = 0x6b206574;
        int x4 = k0, x5 = k1, x6 = k2, x7 = k3, x8 = k4, x9 = k5, x10 = k6, x11 = k7;
        int x12 = counter, x13 = n0, x14 = n1, x15 = n2;
        for (short r = 0; r < 10; r++) {
            x0 += x4; x12 = rotl(x12 ^ x0, (short) 16); x8 += x12; x4 = rotl(x4 ^ x8, (short) 12);
            x0 += x4; x12 = rotl(x12 ^ x0, (short) 8); x8 += x12; x4 = rotl(x4 ^ x8, (short) 7);
            x1 += x5; x13 = rotl(x13 ^ x1, (short) 16); x9 += x13; x5 = rotl(x5 ^ x9, (short) 12);
            x1 += x5; x13 = rotl(x13 ^ x1, (short) 8); x9 += x13; x5 = rotl(x5 ^ x9, (short) 7);
            x2 += x6; x14 = rotl(x14 ^ x2, (short) 16); x10 += x14; x6 = rotl(x6 ^ x10, (short) 12);
            x2 += x6; x14 = rotl(x14 ^ x2, (short) 8); x10 += x14; x6 = rotl(x6 ^ x10, (short) 7);
            x3 += x7; x15 = rotl(x15 ^ x3, (short) 16); x11 += x15; x7 = rotl(x7 ^ x11, (short) 12);
            x3 += x7; x15 = rotl(x15 ^ x3, (short) 8); x11 += x15; x7 = rotl(x7 ^ x11, (short) 7);
            x0 += x5; x15 = rotl(x15 ^ x0, (short) 16); x10 += x15; x5 = rotl(x5 ^ x10, (short) 12);
            x0 += x5; x15 = rotl(x15 ^ x0, (short) 8); x10 += x15; x5 = rotl(x5 ^ x10, (short) 7);
            x1 += x6; x12 = rotl(x12 ^ x1, (short) 16); x11 += x12; x6 = rotl(x6 ^ x11, (short) 12);
            x1 += x6; x12 = rotl(x12 ^ x1, (short) 8); x11 += x12; x6 = rotl(x6 ^ x11, (short) 7);
            x2 += x7; x13 = rotl(x13 ^ x2, (short) 16); x8 += x13; x7 = rotl(x7 ^ x8, (short) 12);
            x2 += x7; x13 = rotl(x13 ^ x2, (short) 8); x8 += x13; x7 = rotl(x7 ^ x8, (short) 7);
            x3 += x4; x14 = rotl(x14 ^ x3, (short) 16); x9 += x14; x4 = rotl(x4 ^ x9, (short) 12);
            x3 += x4; x14 = rotl(x14 ^ x3, (short) 8); x9 += x14; x4 = rotl(x4 ^ x9, (short) 7);
        }
        put32(blk, (short) 0, x0 + 0x61707865);
        put32(blk, (short) 4, x1 + 0x3320646e);
        put32(blk, (short) 8, x2 + 0x79622d32);
        put32(blk, (short) 12, x3 + 0x6b206574);
        put32(blk, (short) 16, x4 + k0);
        put32(blk, (short) 20, x5 + k1);
        put32(blk, (short) 24, x6 + k2);
        put32(blk, (short) 28, x7 + k3);
        put32(blk, (short) 32, x8 + k4);
        put32(blk, (short) 36, x9 + k5);
        put32(blk, (short) 40, x10 + k6);
        put32(blk, (short) 44, x11 + k7);
        put32(blk, (short) 48, x12 + counter);
        put32(blk, (short) 52, x13 + n0);
        put32(blk, (short) 56, x14 + n1);
        put32(blk, (short) 60, x15 + n2);
    }

    /**
     * Seals a Ghost-shaped note: 352-byte plaintext (byte i = i), 40-byte
     * associated data (byte i = 0xA0 + i), key 00..1f, nonce 00..0b. Leaves the
     * tag in mac[48..63] after the call (the first ciphertext bytes are in
     * mac[48..] before the tag is written there) and the first 16 ciphertext
     * bytes in blk[0..15].
     */
    private void aead() {
        short j, k;
        // mac layout: aad(40) pad(8) | ct(352) | len aad(8) | len ct(8)
        Util.arrayFillNonAtomic(mac, (short) 0, (short) 416, (byte) 0);
        for (j = 0; j < 40; j++) {
            mac[j] = (byte) (0xA0 + j);
        }
        for (j = 0; j < 352; j++) {
            mac[(short) (48 + j)] = (byte) j;
        }
        mac[400] = 40;
        mac[409] = 0x01;
        mac[408] = 0x60; // 352 = 0x0160
        // poly key from block 0
        chachaBlock(0);
        short[] p = ph;
        for (j = 0; j < 102; j++) {
            p[j] = 0;
        }
        for (j = 0; j < 16; j++) {
            p[(short) (17 + j)] = (short) (blk[j] & 0xFF);
        }
        p[20] &= 15; p[21] &= 252; p[24] &= 15; p[25] &= 252; p[28] &= 15; p[29] &= 252; p[32] &= 15;
        // keep s = blk[16..31] in g area temporarily (68..83)
        for (j = 0; j < 16; j++) {
            p[(short) (68 + j)] = (short) (blk[(short) (16 + j)] & 0xFF);
        }
        // encrypt
        for (j = 0; j < 352; j += 64) {
            chachaBlock((j / 64) + 1);
            short end = (short) (352 - j);
            if (end > 64) {
                end = 64;
            }
            for (k = 0; k < end; k++) {
                mac[(short) (48 + j + k)] ^= blk[k];
            }
        }
        Util.arrayCopyNonAtomic(mac, (short) 48, blk, (short) 0, (short) 16);
        // poly1305 over all 416 bytes (26 full blocks)
        for (j = 0; j < 416; j += 16) {
            polyBlock(j);
        }
        polyFinish();
    }

    private void polyAdd(short h, short c) {
        short[] p = ph;
        short u = 0;
        for (short j = 0; j < 17; j++) {
            u += (short) (p[(short) (h + j)] + p[(short) (c + j)]);
            p[(short) (h + j)] = (short) (u & 255);
            u = (short) ((u >> 8) & 0xFF);
        }
    }

    private void polyBlock(short off) {
        short[] p = ph;
        short i, j;
        for (j = 0; j < 16; j++) {
            p[(short) (34 + j)] = (short) (mac[(short) (off + j)] & 0xFF);
        }
        p[50] = 1;
        polyAdd((short) 0, (short) 34);
        for (i = 0; i < 17; i++) {
            int x = 0;
            for (j = 0; j <= i; j++) {
                x += (int) p[j] * p[(short) (17 + i - j)];
            }
            for (; j < 17; j++) {
                x += (int) p[j] * 320 * p[(short) (17 + i + 17 - j)];
            }
            p[(short) (51 + i)] = (short) x;
            p[(short) (85 + i)] = (short) (x >>> 16);
        }
        int u = 0;
        for (j = 0; j < 16; j++) {
            u += ((int) p[(short) (85 + j)] << 16) | (p[(short) (51 + j)] & 0xFFFF);
            p[j] = (short) (u & 255);
            u >>>= 8;
        }
        u += ((int) p[101] << 16) | (p[67] & 0xFFFF);
        p[16] = (short) (u & 3);
        u = 5 * (u >>> 2);
        for (j = 0; j < 16; j++) {
            u += p[j];
            p[j] = (short) (u & 255);
            u >>>= 8;
        }
        u += p[16];
        p[16] = (short) u;
    }

    private void polyFinish() {
        short[] p = ph;
        short j;
        // g = h (51..67), c = minus p (34..50)
        for (j = 0; j < 17; j++) {
            p[(short) (51 + j)] = p[j];
            p[(short) (34 + j)] = 0;
        }
        p[34] = 5;
        p[50] = 252;
        polyAdd((short) 0, (short) 34);
        short s = (short) -((p[16] >> 7) & 1);
        for (j = 0; j < 17; j++) {
            p[j] ^= (short) (s & (p[(short) (51 + j)] ^ p[j]));
        }
        for (j = 0; j < 16; j++) {
            p[(short) (34 + j)] = p[(short) (68 + j)];
        }
        p[50] = 0;
        polyAdd((short) 0, (short) 34);
        for (j = 0; j < 16; j++) {
            mac[(short) (48 + j)] = (byte) p[j];
        }
    }

    private static int getInt(byte[] b, short o) {
        return ((int) Util.getShort(b, o) << 16) | (Util.getShort(b, (short) (o + 2)) & 0xFFFF);
    }

    private static void setInt(byte[] b, short o, int v) {
        Util.setShort(b, o, (short) (v >>> 16));
        Util.setShort(b, (short) (o + 2), (short) v);
    }

    // ---------------- LMS: LMS_SHA256_M32_H10 / LMOTS_SHA256_N32_W4 ----------------

    private short hashChainStep() {
        sha.doFinal(lb, (short) 0, (short) 55, lh, (short) 0);
        Util.arrayCopyNonAtomic(lh, (short) 0, lb, (short) 23, (short) 32);
        return 1;
    }

    private void setQ(int q) {
        // I is 16 fixed bytes (0x49), q big-endian
        Util.arrayFillNonAtomic(lb, (short) 0, (short) 16, (byte) 0x49);
        setInt(lb, (short) 16, q);
    }

    /** x_i = H(I || q || i || 0xFF || SEED) into lb[23..54]. */
    private short deriveX(short i) {
        Util.setShort(lb, (short) 20, i);
        lb[22] = (byte) 0xFF;
        Util.arrayCopyNonAtomic(seed, (short) 0, lb, (short) 23, (short) 32);
        return hashChainStep();
    }

    private short digit(short i) {
        // digits 0..63 from Q (lh[32..63]); 64..66 from the checksum in lh[64..65]
        byte v = lh[(short) (32 + (i >> 1))];
        return (short) (((i & 1) == 0 ? (v >> 4) : v) & 0x0F);
    }

    /** One LMS signature over a 200-byte statement. Returns the SHA-256 calls used. */
    private int lmsSign() {
        int hashes = 0;
        // advance the leaf index atomically before signing
        JCSystem.beginTransaction();
        int q = getInt(leafIx, (short) 0);
        setInt(leafIx, (short) 0, (q + 1) & 1023);
        JCSystem.commitTransaction();
        setQ(q & 1023);
        // C random, Q = H(I || q || D_MESG || C || message)
        rng.generateData(lh, (short) 64, (short) 32);
        sha.update(lb, (short) 0, (short) 20);
        lh[0] = (byte) 0x81;
        lh[1] = (byte) 0x81;
        sha.update(lh, (short) 0, (short) 2);
        sha.update(lh, (short) 64, (short) 32);
        sha.update(mac, (short) 0, (short) 200);
        sha.doFinal(seed, (short) 0, (short) 0, lh, (short) 32);
        hashes++;
        // checksum over 64 digits, shifted left by 4, stored after Q
        short ck = 0;
        short i;
        for (i = 0; i < 64; i++) {
            ck += (short) (15 - digit(i));
        }
        Util.setShort(lh, (short) 64, (short) (ck << 4));
        for (i = 0; i < 67; i++) {
            hashes += deriveX(i);
            short a = digit(i);
            for (short j = 0; j < a; j++) {
                lb[22] = (byte) j;
                hashes += hashChainStep();
            }
            // y_i is in lb[23..54]; a real applet streams it out here
        }
        // authentication path: 10 stored nodes
        if (tree0 != null) {
            short node = (short) (1024 + (q & 1023));
            for (i = 0; i < 10; i++) {
                short sib = (short) ((node ^ 1) - 1);
                short off = (short) ((short) (sib % 1023) * 32);
                Util.arrayCopyNonAtomic(sib < 1024 ? tree0 : tree1, off, blk, (short) 0, (short) 32);
                node = (short) (node >> 1);
            }
        }
        return hashes;
    }

    /** Public key and leaf node of LM-OTS leaf q. Returns the SHA-256 calls used. */
    private int lmsLeaf(short q) {
        int hashes = 0;
        setQ(q);
        shaK.update(lb, (short) 0, (short) 20);
        lh[64] = (byte) 0x80;
        lh[65] = (byte) 0x80;
        shaK.update(lh, (short) 64, (short) 2);
        for (short i = 0; i < 67; i++) {
            hashes += deriveX(i);
            for (short j = 0; j < 15; j++) {
                lb[22] = (byte) j;
                hashes += hashChainStep();
            }
            shaK.update(lb, (short) 23, (short) 32);
        }
        shaK.doFinal(lb, (short) 0, (short) 0, lh, (short) 32);
        hashes++;
        // leaf node: H(I || u32(1024 + q) || D_LEAF || K)
        setInt(lb, (short) 16, 1024 + q);
        sha.update(lb, (short) 0, (short) 20);
        lh[64] = (byte) 0x82;
        lh[65] = (byte) 0x82;
        sha.update(lh, (short) 64, (short) 2);
        sha.doFinal(lh, (short) 32, (short) 32, lh, (short) 0);
        hashes++;
        return hashes;
    }

    // ---------------- extended length ----------------

    private void ext(APDU apdu) {
        byte[] buf = apdu.getBuffer();
        short want = Util.getShort(buf, ISO7816.OFFSET_P1);
        short got = apdu.setIncomingAndReceive();
        short total = apdu.getIncomingLength();
        short off = apdu.getOffsetCdata();
        short sum = got;
        sha.update(buf, off, got);
        while (sum < total) {
            got = apdu.receiveBytes(off);
            sha.update(buf, off, got);
            sum += got;
        }
        sha.doFinal(buf, (short) 0, (short) 0, lh, (short) 0);
        short le = apdu.setOutgoing();
        if (want < 34) {
            want = 34;
        }
        apdu.setOutgoingLength(want);
        Util.setShort(lh, (short) 32, total);
        apdu.sendBytesLong(lh, (short) 0, (short) 34);
        Util.arrayFillNonAtomic(mac, (short) 0, (short) 416, (byte) 0x5A);
        short left = (short) (want - 34);
        while (left > 0) {
            short c = left > 416 ? 416 : left;
            apdu.sendBytesLong(mac, (short) 0, c);
            left -= c;
        }
    }
}
