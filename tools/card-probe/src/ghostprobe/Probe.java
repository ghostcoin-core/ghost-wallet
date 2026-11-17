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
    private static final byte INS_KECCAK_F_LOOP = (byte) 0x24;
    private static final byte INS_SHA3_F = (byte) 0x25;
    private static final byte INS_CHACHA_ONLY = (byte) 0x31;
    private static final byte INS_AEAD_FAST = (byte) 0x32;
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
    private short[] kf;   // second state for the unrolled permutation
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
        kf = JCSystem.makeTransientShortArray((short) 100, JCSystem.CLEAR_ON_DESELECT);
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
            out = sha3(buf, apdu.getOffsetCdata(), len, false);
            break;
        }
        case INS_SHA3_F: {
            short len = apdu.setIncomingAndReceive();
            out = sha3(buf, apdu.getOffsetCdata(), len, true);
            break;
        }
        case INS_KECCAK_F_LOOP:
            for (i = 0; i < n; i++) {
                keccakFast();
            }
            break;
        case INS_AEAD_FAST:
            for (i = 0; i < n; i++) {
                aead(true);
            }
            Util.arrayCopyNonAtomic(mac, (short) 48, buf, (short) 0, (short) 16);
            Util.arrayCopyNonAtomic(blk, (short) 0, buf, (short) 16, (short) 16);
            out = 32;
            break;
        case INS_CHACHA_ONLY:
            for (i = 0; i < n; i++) {
                for (short b = 0; b < 7; b++) {
                    chachaBlock(b);
                }
            }
            break;
        case INS_AEAD:
            for (i = 0; i < n; i++) {
                aead(false);
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

    // ---------------- Keccak-f[1600], unrolled (generated) ----------------

    private void keccakFast() {
        short[] a = ks;
        short[] e = kf;
        short c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18, c19;
        short d0, d1, d2, d3, d4, d5, d6, d7, d8, d9, d10, d11, d12, d13, d14, d15, d16, d17, d18, d19;
        short b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15, b16, b17, b18, b19;
        short w0, w1, w2, w3;
        for (short r = 0; r < 96; r += 8) {
            c0 = (short) (a[0] ^ a[20] ^ a[40] ^ a[60] ^ a[80]);
            c1 = (short) (a[1] ^ a[21] ^ a[41] ^ a[61] ^ a[81]);
            c2 = (short) (a[2] ^ a[22] ^ a[42] ^ a[62] ^ a[82]);
            c3 = (short) (a[3] ^ a[23] ^ a[43] ^ a[63] ^ a[83]);
            c4 = (short) (a[4] ^ a[24] ^ a[44] ^ a[64] ^ a[84]);
            c5 = (short) (a[5] ^ a[25] ^ a[45] ^ a[65] ^ a[85]);
            c6 = (short) (a[6] ^ a[26] ^ a[46] ^ a[66] ^ a[86]);
            c7 = (short) (a[7] ^ a[27] ^ a[47] ^ a[67] ^ a[87]);
            c8 = (short) (a[8] ^ a[28] ^ a[48] ^ a[68] ^ a[88]);
            c9 = (short) (a[9] ^ a[29] ^ a[49] ^ a[69] ^ a[89]);
            c10 = (short) (a[10] ^ a[30] ^ a[50] ^ a[70] ^ a[90]);
            c11 = (short) (a[11] ^ a[31] ^ a[51] ^ a[71] ^ a[91]);
            c12 = (short) (a[12] ^ a[32] ^ a[52] ^ a[72] ^ a[92]);
            c13 = (short) (a[13] ^ a[33] ^ a[53] ^ a[73] ^ a[93]);
            c14 = (short) (a[14] ^ a[34] ^ a[54] ^ a[74] ^ a[94]);
            c15 = (short) (a[15] ^ a[35] ^ a[55] ^ a[75] ^ a[95]);
            c16 = (short) (a[16] ^ a[36] ^ a[56] ^ a[76] ^ a[96]);
            c17 = (short) (a[17] ^ a[37] ^ a[57] ^ a[77] ^ a[97]);
            c18 = (short) (a[18] ^ a[38] ^ a[58] ^ a[78] ^ a[98]);
            c19 = (short) (a[19] ^ a[39] ^ a[59] ^ a[79] ^ a[99]);
            d0 = (short) (c16 ^ (short) (c4 << 1) ^ (short) ((c7 >> 15) & 1));
            d1 = (short) (c17 ^ (short) (c5 << 1) ^ (short) ((c4 >> 15) & 1));
            d2 = (short) (c18 ^ (short) (c6 << 1) ^ (short) ((c5 >> 15) & 1));
            d3 = (short) (c19 ^ (short) (c7 << 1) ^ (short) ((c6 >> 15) & 1));
            d4 = (short) (c0 ^ (short) (c8 << 1) ^ (short) ((c11 >> 15) & 1));
            d5 = (short) (c1 ^ (short) (c9 << 1) ^ (short) ((c8 >> 15) & 1));
            d6 = (short) (c2 ^ (short) (c10 << 1) ^ (short) ((c9 >> 15) & 1));
            d7 = (short) (c3 ^ (short) (c11 << 1) ^ (short) ((c10 >> 15) & 1));
            d8 = (short) (c4 ^ (short) (c12 << 1) ^ (short) ((c15 >> 15) & 1));
            d9 = (short) (c5 ^ (short) (c13 << 1) ^ (short) ((c12 >> 15) & 1));
            d10 = (short) (c6 ^ (short) (c14 << 1) ^ (short) ((c13 >> 15) & 1));
            d11 = (short) (c7 ^ (short) (c15 << 1) ^ (short) ((c14 >> 15) & 1));
            d12 = (short) (c8 ^ (short) (c16 << 1) ^ (short) ((c19 >> 15) & 1));
            d13 = (short) (c9 ^ (short) (c17 << 1) ^ (short) ((c16 >> 15) & 1));
            d14 = (short) (c10 ^ (short) (c18 << 1) ^ (short) ((c17 >> 15) & 1));
            d15 = (short) (c11 ^ (short) (c19 << 1) ^ (short) ((c18 >> 15) & 1));
            d16 = (short) (c12 ^ (short) (c0 << 1) ^ (short) ((c3 >> 15) & 1));
            d17 = (short) (c13 ^ (short) (c1 << 1) ^ (short) ((c0 >> 15) & 1));
            d18 = (short) (c14 ^ (short) (c2 << 1) ^ (short) ((c1 >> 15) & 1));
            d19 = (short) (c15 ^ (short) (c3 << 1) ^ (short) ((c2 >> 15) & 1));
            w0 = (short) (a[0] ^ d0);
            w1 = (short) (a[1] ^ d1);
            w2 = (short) (a[2] ^ d2);
            w3 = (short) (a[3] ^ d3);
            b0 = w0;
            b1 = w1;
            b2 = w2;
            b3 = w3;
            w0 = (short) (a[24] ^ d4);
            w1 = (short) (a[25] ^ d5);
            w2 = (short) (a[26] ^ d6);
            w3 = (short) (a[27] ^ d7);
            b4 = (short) ((short) (w2 << 12) | (short) ((short) (w1 >> 4) & 4095));
            b5 = (short) ((short) (w3 << 12) | (short) ((short) (w2 >> 4) & 4095));
            b6 = (short) ((short) (w0 << 12) | (short) ((short) (w3 >> 4) & 4095));
            b7 = (short) ((short) (w1 << 12) | (short) ((short) (w0 >> 4) & 4095));
            w0 = (short) (a[48] ^ d8);
            w1 = (short) (a[49] ^ d9);
            w2 = (short) (a[50] ^ d10);
            w3 = (short) (a[51] ^ d11);
            b8 = (short) ((short) (w2 << 11) | (short) ((short) (w1 >> 5) & 2047));
            b9 = (short) ((short) (w3 << 11) | (short) ((short) (w2 >> 5) & 2047));
            b10 = (short) ((short) (w0 << 11) | (short) ((short) (w3 >> 5) & 2047));
            b11 = (short) ((short) (w1 << 11) | (short) ((short) (w0 >> 5) & 2047));
            w0 = (short) (a[72] ^ d12);
            w1 = (short) (a[73] ^ d13);
            w2 = (short) (a[74] ^ d14);
            w3 = (short) (a[75] ^ d15);
            b12 = (short) ((short) (w3 << 5) | (short) ((short) (w2 >> 11) & 31));
            b13 = (short) ((short) (w0 << 5) | (short) ((short) (w3 >> 11) & 31));
            b14 = (short) ((short) (w1 << 5) | (short) ((short) (w0 >> 11) & 31));
            b15 = (short) ((short) (w2 << 5) | (short) ((short) (w1 >> 11) & 31));
            w0 = (short) (a[96] ^ d16);
            w1 = (short) (a[97] ^ d17);
            w2 = (short) (a[98] ^ d18);
            w3 = (short) (a[99] ^ d19);
            b16 = (short) ((short) (w0 << 14) | (short) ((short) (w3 >> 2) & 16383));
            b17 = (short) ((short) (w1 << 14) | (short) ((short) (w0 >> 2) & 16383));
            b18 = (short) ((short) (w2 << 14) | (short) ((short) (w1 >> 2) & 16383));
            b19 = (short) ((short) (w3 << 14) | (short) ((short) (w2 >> 2) & 16383));
            e[0] = (short) ((short) (b0 ^ (short) (~b4 & b8)) ^ RCS[(short) (r + 0)]);
            e[1] = (short) ((short) (b1 ^ (short) (~b5 & b9)) ^ RCS[(short) (r + 1)]);
            e[2] = (short) ((short) (b2 ^ (short) (~b6 & b10)) ^ RCS[(short) (r + 2)]);
            e[3] = (short) ((short) (b3 ^ (short) (~b7 & b11)) ^ RCS[(short) (r + 3)]);
            e[4] = (short) (b4 ^ (short) (~b8 & b12));
            e[5] = (short) (b5 ^ (short) (~b9 & b13));
            e[6] = (short) (b6 ^ (short) (~b10 & b14));
            e[7] = (short) (b7 ^ (short) (~b11 & b15));
            e[8] = (short) (b8 ^ (short) (~b12 & b16));
            e[9] = (short) (b9 ^ (short) (~b13 & b17));
            e[10] = (short) (b10 ^ (short) (~b14 & b18));
            e[11] = (short) (b11 ^ (short) (~b15 & b19));
            e[12] = (short) (b12 ^ (short) (~b16 & b0));
            e[13] = (short) (b13 ^ (short) (~b17 & b1));
            e[14] = (short) (b14 ^ (short) (~b18 & b2));
            e[15] = (short) (b15 ^ (short) (~b19 & b3));
            e[16] = (short) (b16 ^ (short) (~b0 & b4));
            e[17] = (short) (b17 ^ (short) (~b1 & b5));
            e[18] = (short) (b18 ^ (short) (~b2 & b6));
            e[19] = (short) (b19 ^ (short) (~b3 & b7));
            w0 = (short) (a[12] ^ d12);
            w1 = (short) (a[13] ^ d13);
            w2 = (short) (a[14] ^ d14);
            w3 = (short) (a[15] ^ d15);
            b0 = (short) ((short) (w3 << 12) | (short) ((short) (w2 >> 4) & 4095));
            b1 = (short) ((short) (w0 << 12) | (short) ((short) (w3 >> 4) & 4095));
            b2 = (short) ((short) (w1 << 12) | (short) ((short) (w0 >> 4) & 4095));
            b3 = (short) ((short) (w2 << 12) | (short) ((short) (w1 >> 4) & 4095));
            w0 = (short) (a[36] ^ d16);
            w1 = (short) (a[37] ^ d17);
            w2 = (short) (a[38] ^ d18);
            w3 = (short) (a[39] ^ d19);
            b4 = (short) ((short) (w3 << 4) | (short) ((short) (w2 >> 12) & 15));
            b5 = (short) ((short) (w0 << 4) | (short) ((short) (w3 >> 12) & 15));
            b6 = (short) ((short) (w1 << 4) | (short) ((short) (w0 >> 12) & 15));
            b7 = (short) ((short) (w2 << 4) | (short) ((short) (w1 >> 12) & 15));
            w0 = (short) (a[40] ^ d0);
            w1 = (short) (a[41] ^ d1);
            w2 = (short) (a[42] ^ d2);
            w3 = (short) (a[43] ^ d3);
            b8 = (short) ((short) (w0 << 3) | (short) ((short) (w3 >> 13) & 7));
            b9 = (short) ((short) (w1 << 3) | (short) ((short) (w0 >> 13) & 7));
            b10 = (short) ((short) (w2 << 3) | (short) ((short) (w1 >> 13) & 7));
            b11 = (short) ((short) (w3 << 3) | (short) ((short) (w2 >> 13) & 7));
            w0 = (short) (a[64] ^ d4);
            w1 = (short) (a[65] ^ d5);
            w2 = (short) (a[66] ^ d6);
            w3 = (short) (a[67] ^ d7);
            b12 = (short) ((short) (w2 << 13) | (short) ((short) (w1 >> 3) & 8191));
            b13 = (short) ((short) (w3 << 13) | (short) ((short) (w2 >> 3) & 8191));
            b14 = (short) ((short) (w0 << 13) | (short) ((short) (w3 >> 3) & 8191));
            b15 = (short) ((short) (w1 << 13) | (short) ((short) (w0 >> 3) & 8191));
            w0 = (short) (a[88] ^ d8);
            w1 = (short) (a[89] ^ d9);
            w2 = (short) (a[90] ^ d10);
            w3 = (short) (a[91] ^ d11);
            b16 = (short) ((short) (w1 << 13) | (short) ((short) (w0 >> 3) & 8191));
            b17 = (short) ((short) (w2 << 13) | (short) ((short) (w1 >> 3) & 8191));
            b18 = (short) ((short) (w3 << 13) | (short) ((short) (w2 >> 3) & 8191));
            b19 = (short) ((short) (w0 << 13) | (short) ((short) (w3 >> 3) & 8191));
            e[20] = (short) (b0 ^ (short) (~b4 & b8));
            e[21] = (short) (b1 ^ (short) (~b5 & b9));
            e[22] = (short) (b2 ^ (short) (~b6 & b10));
            e[23] = (short) (b3 ^ (short) (~b7 & b11));
            e[24] = (short) (b4 ^ (short) (~b8 & b12));
            e[25] = (short) (b5 ^ (short) (~b9 & b13));
            e[26] = (short) (b6 ^ (short) (~b10 & b14));
            e[27] = (short) (b7 ^ (short) (~b11 & b15));
            e[28] = (short) (b8 ^ (short) (~b12 & b16));
            e[29] = (short) (b9 ^ (short) (~b13 & b17));
            e[30] = (short) (b10 ^ (short) (~b14 & b18));
            e[31] = (short) (b11 ^ (short) (~b15 & b19));
            e[32] = (short) (b12 ^ (short) (~b16 & b0));
            e[33] = (short) (b13 ^ (short) (~b17 & b1));
            e[34] = (short) (b14 ^ (short) (~b18 & b2));
            e[35] = (short) (b15 ^ (short) (~b19 & b3));
            e[36] = (short) (b16 ^ (short) (~b0 & b4));
            e[37] = (short) (b17 ^ (short) (~b1 & b5));
            e[38] = (short) (b18 ^ (short) (~b2 & b6));
            e[39] = (short) (b19 ^ (short) (~b3 & b7));
            w0 = (short) (a[4] ^ d4);
            w1 = (short) (a[5] ^ d5);
            w2 = (short) (a[6] ^ d6);
            w3 = (short) (a[7] ^ d7);
            b0 = (short) ((short) (w0 << 1) | (short) ((short) (w3 >> 15) & 1));
            b1 = (short) ((short) (w1 << 1) | (short) ((short) (w0 >> 15) & 1));
            b2 = (short) ((short) (w2 << 1) | (short) ((short) (w1 >> 15) & 1));
            b3 = (short) ((short) (w3 << 1) | (short) ((short) (w2 >> 15) & 1));
            w0 = (short) (a[28] ^ d8);
            w1 = (short) (a[29] ^ d9);
            w2 = (short) (a[30] ^ d10);
            w3 = (short) (a[31] ^ d11);
            b4 = (short) ((short) (w0 << 6) | (short) ((short) (w3 >> 10) & 63));
            b5 = (short) ((short) (w1 << 6) | (short) ((short) (w0 >> 10) & 63));
            b6 = (short) ((short) (w2 << 6) | (short) ((short) (w1 >> 10) & 63));
            b7 = (short) ((short) (w3 << 6) | (short) ((short) (w2 >> 10) & 63));
            w0 = (short) (a[52] ^ d12);
            w1 = (short) (a[53] ^ d13);
            w2 = (short) (a[54] ^ d14);
            w3 = (short) (a[55] ^ d15);
            b8 = (short) ((short) (w3 << 9) | (short) ((short) (w2 >> 7) & 511));
            b9 = (short) ((short) (w0 << 9) | (short) ((short) (w3 >> 7) & 511));
            b10 = (short) ((short) (w1 << 9) | (short) ((short) (w0 >> 7) & 511));
            b11 = (short) ((short) (w2 << 9) | (short) ((short) (w1 >> 7) & 511));
            w0 = (short) (a[76] ^ d16);
            w1 = (short) (a[77] ^ d17);
            w2 = (short) (a[78] ^ d18);
            w3 = (short) (a[79] ^ d19);
            b12 = (short) ((short) (w0 << 8) | (short) ((short) (w3 >> 8) & 255));
            b13 = (short) ((short) (w1 << 8) | (short) ((short) (w0 >> 8) & 255));
            b14 = (short) ((short) (w2 << 8) | (short) ((short) (w1 >> 8) & 255));
            b15 = (short) ((short) (w3 << 8) | (short) ((short) (w2 >> 8) & 255));
            w0 = (short) (a[80] ^ d0);
            w1 = (short) (a[81] ^ d1);
            w2 = (short) (a[82] ^ d2);
            w3 = (short) (a[83] ^ d3);
            b16 = (short) ((short) (w3 << 2) | (short) ((short) (w2 >> 14) & 3));
            b17 = (short) ((short) (w0 << 2) | (short) ((short) (w3 >> 14) & 3));
            b18 = (short) ((short) (w1 << 2) | (short) ((short) (w0 >> 14) & 3));
            b19 = (short) ((short) (w2 << 2) | (short) ((short) (w1 >> 14) & 3));
            e[40] = (short) (b0 ^ (short) (~b4 & b8));
            e[41] = (short) (b1 ^ (short) (~b5 & b9));
            e[42] = (short) (b2 ^ (short) (~b6 & b10));
            e[43] = (short) (b3 ^ (short) (~b7 & b11));
            e[44] = (short) (b4 ^ (short) (~b8 & b12));
            e[45] = (short) (b5 ^ (short) (~b9 & b13));
            e[46] = (short) (b6 ^ (short) (~b10 & b14));
            e[47] = (short) (b7 ^ (short) (~b11 & b15));
            e[48] = (short) (b8 ^ (short) (~b12 & b16));
            e[49] = (short) (b9 ^ (short) (~b13 & b17));
            e[50] = (short) (b10 ^ (short) (~b14 & b18));
            e[51] = (short) (b11 ^ (short) (~b15 & b19));
            e[52] = (short) (b12 ^ (short) (~b16 & b0));
            e[53] = (short) (b13 ^ (short) (~b17 & b1));
            e[54] = (short) (b14 ^ (short) (~b18 & b2));
            e[55] = (short) (b15 ^ (short) (~b19 & b3));
            e[56] = (short) (b16 ^ (short) (~b0 & b4));
            e[57] = (short) (b17 ^ (short) (~b1 & b5));
            e[58] = (short) (b18 ^ (short) (~b2 & b6));
            e[59] = (short) (b19 ^ (short) (~b3 & b7));
            w0 = (short) (a[16] ^ d16);
            w1 = (short) (a[17] ^ d17);
            w2 = (short) (a[18] ^ d18);
            w3 = (short) (a[19] ^ d19);
            b0 = (short) ((short) (w3 << 11) | (short) ((short) (w2 >> 5) & 2047));
            b1 = (short) ((short) (w0 << 11) | (short) ((short) (w3 >> 5) & 2047));
            b2 = (short) ((short) (w1 << 11) | (short) ((short) (w0 >> 5) & 2047));
            b3 = (short) ((short) (w2 << 11) | (short) ((short) (w1 >> 5) & 2047));
            w0 = (short) (a[20] ^ d0);
            w1 = (short) (a[21] ^ d1);
            w2 = (short) (a[22] ^ d2);
            w3 = (short) (a[23] ^ d3);
            b4 = (short) ((short) (w2 << 4) | (short) ((short) (w1 >> 12) & 15));
            b5 = (short) ((short) (w3 << 4) | (short) ((short) (w2 >> 12) & 15));
            b6 = (short) ((short) (w0 << 4) | (short) ((short) (w3 >> 12) & 15));
            b7 = (short) ((short) (w1 << 4) | (short) ((short) (w0 >> 12) & 15));
            w0 = (short) (a[44] ^ d4);
            w1 = (short) (a[45] ^ d5);
            w2 = (short) (a[46] ^ d6);
            w3 = (short) (a[47] ^ d7);
            b8 = (short) ((short) (w0 << 10) | (short) ((short) (w3 >> 6) & 1023));
            b9 = (short) ((short) (w1 << 10) | (short) ((short) (w0 >> 6) & 1023));
            b10 = (short) ((short) (w2 << 10) | (short) ((short) (w1 >> 6) & 1023));
            b11 = (short) ((short) (w3 << 10) | (short) ((short) (w2 >> 6) & 1023));
            w0 = (short) (a[68] ^ d8);
            w1 = (short) (a[69] ^ d9);
            w2 = (short) (a[70] ^ d10);
            w3 = (short) (a[71] ^ d11);
            b12 = (short) ((short) (w0 << 15) | (short) ((short) (w3 >> 1) & 32767));
            b13 = (short) ((short) (w1 << 15) | (short) ((short) (w0 >> 1) & 32767));
            b14 = (short) ((short) (w2 << 15) | (short) ((short) (w1 >> 1) & 32767));
            b15 = (short) ((short) (w3 << 15) | (short) ((short) (w2 >> 1) & 32767));
            w0 = (short) (a[92] ^ d12);
            w1 = (short) (a[93] ^ d13);
            w2 = (short) (a[94] ^ d14);
            w3 = (short) (a[95] ^ d15);
            b16 = (short) ((short) (w1 << 8) | (short) ((short) (w0 >> 8) & 255));
            b17 = (short) ((short) (w2 << 8) | (short) ((short) (w1 >> 8) & 255));
            b18 = (short) ((short) (w3 << 8) | (short) ((short) (w2 >> 8) & 255));
            b19 = (short) ((short) (w0 << 8) | (short) ((short) (w3 >> 8) & 255));
            e[60] = (short) (b0 ^ (short) (~b4 & b8));
            e[61] = (short) (b1 ^ (short) (~b5 & b9));
            e[62] = (short) (b2 ^ (short) (~b6 & b10));
            e[63] = (short) (b3 ^ (short) (~b7 & b11));
            e[64] = (short) (b4 ^ (short) (~b8 & b12));
            e[65] = (short) (b5 ^ (short) (~b9 & b13));
            e[66] = (short) (b6 ^ (short) (~b10 & b14));
            e[67] = (short) (b7 ^ (short) (~b11 & b15));
            e[68] = (short) (b8 ^ (short) (~b12 & b16));
            e[69] = (short) (b9 ^ (short) (~b13 & b17));
            e[70] = (short) (b10 ^ (short) (~b14 & b18));
            e[71] = (short) (b11 ^ (short) (~b15 & b19));
            e[72] = (short) (b12 ^ (short) (~b16 & b0));
            e[73] = (short) (b13 ^ (short) (~b17 & b1));
            e[74] = (short) (b14 ^ (short) (~b18 & b2));
            e[75] = (short) (b15 ^ (short) (~b19 & b3));
            e[76] = (short) (b16 ^ (short) (~b0 & b4));
            e[77] = (short) (b17 ^ (short) (~b1 & b5));
            e[78] = (short) (b18 ^ (short) (~b2 & b6));
            e[79] = (short) (b19 ^ (short) (~b3 & b7));
            w0 = (short) (a[8] ^ d8);
            w1 = (short) (a[9] ^ d9);
            w2 = (short) (a[10] ^ d10);
            w3 = (short) (a[11] ^ d11);
            b0 = (short) ((short) (w1 << 14) | (short) ((short) (w0 >> 2) & 16383));
            b1 = (short) ((short) (w2 << 14) | (short) ((short) (w1 >> 2) & 16383));
            b2 = (short) ((short) (w3 << 14) | (short) ((short) (w2 >> 2) & 16383));
            b3 = (short) ((short) (w0 << 14) | (short) ((short) (w3 >> 2) & 16383));
            w0 = (short) (a[32] ^ d12);
            w1 = (short) (a[33] ^ d13);
            w2 = (short) (a[34] ^ d14);
            w3 = (short) (a[35] ^ d15);
            b4 = (short) ((short) (w1 << 7) | (short) ((short) (w0 >> 9) & 127));
            b5 = (short) ((short) (w2 << 7) | (short) ((short) (w1 >> 9) & 127));
            b6 = (short) ((short) (w3 << 7) | (short) ((short) (w2 >> 9) & 127));
            b7 = (short) ((short) (w0 << 7) | (short) ((short) (w3 >> 9) & 127));
            w0 = (short) (a[56] ^ d16);
            w1 = (short) (a[57] ^ d17);
            w2 = (short) (a[58] ^ d18);
            w3 = (short) (a[59] ^ d19);
            b8 = (short) ((short) (w2 << 7) | (short) ((short) (w1 >> 9) & 127));
            b9 = (short) ((short) (w3 << 7) | (short) ((short) (w2 >> 9) & 127));
            b10 = (short) ((short) (w0 << 7) | (short) ((short) (w3 >> 9) & 127));
            b11 = (short) ((short) (w1 << 7) | (short) ((short) (w0 >> 9) & 127));
            w0 = (short) (a[60] ^ d0);
            w1 = (short) (a[61] ^ d1);
            w2 = (short) (a[62] ^ d2);
            w3 = (short) (a[63] ^ d3);
            b12 = (short) ((short) (w2 << 9) | (short) ((short) (w1 >> 7) & 511));
            b13 = (short) ((short) (w3 << 9) | (short) ((short) (w2 >> 7) & 511));
            b14 = (short) ((short) (w0 << 9) | (short) ((short) (w3 >> 7) & 511));
            b15 = (short) ((short) (w1 << 9) | (short) ((short) (w0 >> 7) & 511));
            w0 = (short) (a[84] ^ d4);
            w1 = (short) (a[85] ^ d5);
            w2 = (short) (a[86] ^ d6);
            w3 = (short) (a[87] ^ d7);
            b16 = (short) ((short) (w0 << 2) | (short) ((short) (w3 >> 14) & 3));
            b17 = (short) ((short) (w1 << 2) | (short) ((short) (w0 >> 14) & 3));
            b18 = (short) ((short) (w2 << 2) | (short) ((short) (w1 >> 14) & 3));
            b19 = (short) ((short) (w3 << 2) | (short) ((short) (w2 >> 14) & 3));
            e[80] = (short) (b0 ^ (short) (~b4 & b8));
            e[81] = (short) (b1 ^ (short) (~b5 & b9));
            e[82] = (short) (b2 ^ (short) (~b6 & b10));
            e[83] = (short) (b3 ^ (short) (~b7 & b11));
            e[84] = (short) (b4 ^ (short) (~b8 & b12));
            e[85] = (short) (b5 ^ (short) (~b9 & b13));
            e[86] = (short) (b6 ^ (short) (~b10 & b14));
            e[87] = (short) (b7 ^ (short) (~b11 & b15));
            e[88] = (short) (b8 ^ (short) (~b12 & b16));
            e[89] = (short) (b9 ^ (short) (~b13 & b17));
            e[90] = (short) (b10 ^ (short) (~b14 & b18));
            e[91] = (short) (b11 ^ (short) (~b15 & b19));
            e[92] = (short) (b12 ^ (short) (~b16 & b0));
            e[93] = (short) (b13 ^ (short) (~b17 & b1));
            e[94] = (short) (b14 ^ (short) (~b18 & b2));
            e[95] = (short) (b15 ^ (short) (~b19 & b3));
            e[96] = (short) (b16 ^ (short) (~b0 & b4));
            e[97] = (short) (b17 ^ (short) (~b1 & b5));
            e[98] = (short) (b18 ^ (short) (~b2 & b6));
            e[99] = (short) (b19 ^ (short) (~b3 & b7));
            c0 = (short) (e[0] ^ e[20] ^ e[40] ^ e[60] ^ e[80]);
            c1 = (short) (e[1] ^ e[21] ^ e[41] ^ e[61] ^ e[81]);
            c2 = (short) (e[2] ^ e[22] ^ e[42] ^ e[62] ^ e[82]);
            c3 = (short) (e[3] ^ e[23] ^ e[43] ^ e[63] ^ e[83]);
            c4 = (short) (e[4] ^ e[24] ^ e[44] ^ e[64] ^ e[84]);
            c5 = (short) (e[5] ^ e[25] ^ e[45] ^ e[65] ^ e[85]);
            c6 = (short) (e[6] ^ e[26] ^ e[46] ^ e[66] ^ e[86]);
            c7 = (short) (e[7] ^ e[27] ^ e[47] ^ e[67] ^ e[87]);
            c8 = (short) (e[8] ^ e[28] ^ e[48] ^ e[68] ^ e[88]);
            c9 = (short) (e[9] ^ e[29] ^ e[49] ^ e[69] ^ e[89]);
            c10 = (short) (e[10] ^ e[30] ^ e[50] ^ e[70] ^ e[90]);
            c11 = (short) (e[11] ^ e[31] ^ e[51] ^ e[71] ^ e[91]);
            c12 = (short) (e[12] ^ e[32] ^ e[52] ^ e[72] ^ e[92]);
            c13 = (short) (e[13] ^ e[33] ^ e[53] ^ e[73] ^ e[93]);
            c14 = (short) (e[14] ^ e[34] ^ e[54] ^ e[74] ^ e[94]);
            c15 = (short) (e[15] ^ e[35] ^ e[55] ^ e[75] ^ e[95]);
            c16 = (short) (e[16] ^ e[36] ^ e[56] ^ e[76] ^ e[96]);
            c17 = (short) (e[17] ^ e[37] ^ e[57] ^ e[77] ^ e[97]);
            c18 = (short) (e[18] ^ e[38] ^ e[58] ^ e[78] ^ e[98]);
            c19 = (short) (e[19] ^ e[39] ^ e[59] ^ e[79] ^ e[99]);
            d0 = (short) (c16 ^ (short) (c4 << 1) ^ (short) ((c7 >> 15) & 1));
            d1 = (short) (c17 ^ (short) (c5 << 1) ^ (short) ((c4 >> 15) & 1));
            d2 = (short) (c18 ^ (short) (c6 << 1) ^ (short) ((c5 >> 15) & 1));
            d3 = (short) (c19 ^ (short) (c7 << 1) ^ (short) ((c6 >> 15) & 1));
            d4 = (short) (c0 ^ (short) (c8 << 1) ^ (short) ((c11 >> 15) & 1));
            d5 = (short) (c1 ^ (short) (c9 << 1) ^ (short) ((c8 >> 15) & 1));
            d6 = (short) (c2 ^ (short) (c10 << 1) ^ (short) ((c9 >> 15) & 1));
            d7 = (short) (c3 ^ (short) (c11 << 1) ^ (short) ((c10 >> 15) & 1));
            d8 = (short) (c4 ^ (short) (c12 << 1) ^ (short) ((c15 >> 15) & 1));
            d9 = (short) (c5 ^ (short) (c13 << 1) ^ (short) ((c12 >> 15) & 1));
            d10 = (short) (c6 ^ (short) (c14 << 1) ^ (short) ((c13 >> 15) & 1));
            d11 = (short) (c7 ^ (short) (c15 << 1) ^ (short) ((c14 >> 15) & 1));
            d12 = (short) (c8 ^ (short) (c16 << 1) ^ (short) ((c19 >> 15) & 1));
            d13 = (short) (c9 ^ (short) (c17 << 1) ^ (short) ((c16 >> 15) & 1));
            d14 = (short) (c10 ^ (short) (c18 << 1) ^ (short) ((c17 >> 15) & 1));
            d15 = (short) (c11 ^ (short) (c19 << 1) ^ (short) ((c18 >> 15) & 1));
            d16 = (short) (c12 ^ (short) (c0 << 1) ^ (short) ((c3 >> 15) & 1));
            d17 = (short) (c13 ^ (short) (c1 << 1) ^ (short) ((c0 >> 15) & 1));
            d18 = (short) (c14 ^ (short) (c2 << 1) ^ (short) ((c1 >> 15) & 1));
            d19 = (short) (c15 ^ (short) (c3 << 1) ^ (short) ((c2 >> 15) & 1));
            w0 = (short) (e[0] ^ d0);
            w1 = (short) (e[1] ^ d1);
            w2 = (short) (e[2] ^ d2);
            w3 = (short) (e[3] ^ d3);
            b0 = w0;
            b1 = w1;
            b2 = w2;
            b3 = w3;
            w0 = (short) (e[24] ^ d4);
            w1 = (short) (e[25] ^ d5);
            w2 = (short) (e[26] ^ d6);
            w3 = (short) (e[27] ^ d7);
            b4 = (short) ((short) (w2 << 12) | (short) ((short) (w1 >> 4) & 4095));
            b5 = (short) ((short) (w3 << 12) | (short) ((short) (w2 >> 4) & 4095));
            b6 = (short) ((short) (w0 << 12) | (short) ((short) (w3 >> 4) & 4095));
            b7 = (short) ((short) (w1 << 12) | (short) ((short) (w0 >> 4) & 4095));
            w0 = (short) (e[48] ^ d8);
            w1 = (short) (e[49] ^ d9);
            w2 = (short) (e[50] ^ d10);
            w3 = (short) (e[51] ^ d11);
            b8 = (short) ((short) (w2 << 11) | (short) ((short) (w1 >> 5) & 2047));
            b9 = (short) ((short) (w3 << 11) | (short) ((short) (w2 >> 5) & 2047));
            b10 = (short) ((short) (w0 << 11) | (short) ((short) (w3 >> 5) & 2047));
            b11 = (short) ((short) (w1 << 11) | (short) ((short) (w0 >> 5) & 2047));
            w0 = (short) (e[72] ^ d12);
            w1 = (short) (e[73] ^ d13);
            w2 = (short) (e[74] ^ d14);
            w3 = (short) (e[75] ^ d15);
            b12 = (short) ((short) (w3 << 5) | (short) ((short) (w2 >> 11) & 31));
            b13 = (short) ((short) (w0 << 5) | (short) ((short) (w3 >> 11) & 31));
            b14 = (short) ((short) (w1 << 5) | (short) ((short) (w0 >> 11) & 31));
            b15 = (short) ((short) (w2 << 5) | (short) ((short) (w1 >> 11) & 31));
            w0 = (short) (e[96] ^ d16);
            w1 = (short) (e[97] ^ d17);
            w2 = (short) (e[98] ^ d18);
            w3 = (short) (e[99] ^ d19);
            b16 = (short) ((short) (w0 << 14) | (short) ((short) (w3 >> 2) & 16383));
            b17 = (short) ((short) (w1 << 14) | (short) ((short) (w0 >> 2) & 16383));
            b18 = (short) ((short) (w2 << 14) | (short) ((short) (w1 >> 2) & 16383));
            b19 = (short) ((short) (w3 << 14) | (short) ((short) (w2 >> 2) & 16383));
            a[0] = (short) ((short) (b0 ^ (short) (~b4 & b8)) ^ RCS[(short) ((short) (r + 4) + 0)]);
            a[1] = (short) ((short) (b1 ^ (short) (~b5 & b9)) ^ RCS[(short) ((short) (r + 4) + 1)]);
            a[2] = (short) ((short) (b2 ^ (short) (~b6 & b10)) ^ RCS[(short) ((short) (r + 4) + 2)]);
            a[3] = (short) ((short) (b3 ^ (short) (~b7 & b11)) ^ RCS[(short) ((short) (r + 4) + 3)]);
            a[4] = (short) (b4 ^ (short) (~b8 & b12));
            a[5] = (short) (b5 ^ (short) (~b9 & b13));
            a[6] = (short) (b6 ^ (short) (~b10 & b14));
            a[7] = (short) (b7 ^ (short) (~b11 & b15));
            a[8] = (short) (b8 ^ (short) (~b12 & b16));
            a[9] = (short) (b9 ^ (short) (~b13 & b17));
            a[10] = (short) (b10 ^ (short) (~b14 & b18));
            a[11] = (short) (b11 ^ (short) (~b15 & b19));
            a[12] = (short) (b12 ^ (short) (~b16 & b0));
            a[13] = (short) (b13 ^ (short) (~b17 & b1));
            a[14] = (short) (b14 ^ (short) (~b18 & b2));
            a[15] = (short) (b15 ^ (short) (~b19 & b3));
            a[16] = (short) (b16 ^ (short) (~b0 & b4));
            a[17] = (short) (b17 ^ (short) (~b1 & b5));
            a[18] = (short) (b18 ^ (short) (~b2 & b6));
            a[19] = (short) (b19 ^ (short) (~b3 & b7));
            w0 = (short) (e[12] ^ d12);
            w1 = (short) (e[13] ^ d13);
            w2 = (short) (e[14] ^ d14);
            w3 = (short) (e[15] ^ d15);
            b0 = (short) ((short) (w3 << 12) | (short) ((short) (w2 >> 4) & 4095));
            b1 = (short) ((short) (w0 << 12) | (short) ((short) (w3 >> 4) & 4095));
            b2 = (short) ((short) (w1 << 12) | (short) ((short) (w0 >> 4) & 4095));
            b3 = (short) ((short) (w2 << 12) | (short) ((short) (w1 >> 4) & 4095));
            w0 = (short) (e[36] ^ d16);
            w1 = (short) (e[37] ^ d17);
            w2 = (short) (e[38] ^ d18);
            w3 = (short) (e[39] ^ d19);
            b4 = (short) ((short) (w3 << 4) | (short) ((short) (w2 >> 12) & 15));
            b5 = (short) ((short) (w0 << 4) | (short) ((short) (w3 >> 12) & 15));
            b6 = (short) ((short) (w1 << 4) | (short) ((short) (w0 >> 12) & 15));
            b7 = (short) ((short) (w2 << 4) | (short) ((short) (w1 >> 12) & 15));
            w0 = (short) (e[40] ^ d0);
            w1 = (short) (e[41] ^ d1);
            w2 = (short) (e[42] ^ d2);
            w3 = (short) (e[43] ^ d3);
            b8 = (short) ((short) (w0 << 3) | (short) ((short) (w3 >> 13) & 7));
            b9 = (short) ((short) (w1 << 3) | (short) ((short) (w0 >> 13) & 7));
            b10 = (short) ((short) (w2 << 3) | (short) ((short) (w1 >> 13) & 7));
            b11 = (short) ((short) (w3 << 3) | (short) ((short) (w2 >> 13) & 7));
            w0 = (short) (e[64] ^ d4);
            w1 = (short) (e[65] ^ d5);
            w2 = (short) (e[66] ^ d6);
            w3 = (short) (e[67] ^ d7);
            b12 = (short) ((short) (w2 << 13) | (short) ((short) (w1 >> 3) & 8191));
            b13 = (short) ((short) (w3 << 13) | (short) ((short) (w2 >> 3) & 8191));
            b14 = (short) ((short) (w0 << 13) | (short) ((short) (w3 >> 3) & 8191));
            b15 = (short) ((short) (w1 << 13) | (short) ((short) (w0 >> 3) & 8191));
            w0 = (short) (e[88] ^ d8);
            w1 = (short) (e[89] ^ d9);
            w2 = (short) (e[90] ^ d10);
            w3 = (short) (e[91] ^ d11);
            b16 = (short) ((short) (w1 << 13) | (short) ((short) (w0 >> 3) & 8191));
            b17 = (short) ((short) (w2 << 13) | (short) ((short) (w1 >> 3) & 8191));
            b18 = (short) ((short) (w3 << 13) | (short) ((short) (w2 >> 3) & 8191));
            b19 = (short) ((short) (w0 << 13) | (short) ((short) (w3 >> 3) & 8191));
            a[20] = (short) (b0 ^ (short) (~b4 & b8));
            a[21] = (short) (b1 ^ (short) (~b5 & b9));
            a[22] = (short) (b2 ^ (short) (~b6 & b10));
            a[23] = (short) (b3 ^ (short) (~b7 & b11));
            a[24] = (short) (b4 ^ (short) (~b8 & b12));
            a[25] = (short) (b5 ^ (short) (~b9 & b13));
            a[26] = (short) (b6 ^ (short) (~b10 & b14));
            a[27] = (short) (b7 ^ (short) (~b11 & b15));
            a[28] = (short) (b8 ^ (short) (~b12 & b16));
            a[29] = (short) (b9 ^ (short) (~b13 & b17));
            a[30] = (short) (b10 ^ (short) (~b14 & b18));
            a[31] = (short) (b11 ^ (short) (~b15 & b19));
            a[32] = (short) (b12 ^ (short) (~b16 & b0));
            a[33] = (short) (b13 ^ (short) (~b17 & b1));
            a[34] = (short) (b14 ^ (short) (~b18 & b2));
            a[35] = (short) (b15 ^ (short) (~b19 & b3));
            a[36] = (short) (b16 ^ (short) (~b0 & b4));
            a[37] = (short) (b17 ^ (short) (~b1 & b5));
            a[38] = (short) (b18 ^ (short) (~b2 & b6));
            a[39] = (short) (b19 ^ (short) (~b3 & b7));
            w0 = (short) (e[4] ^ d4);
            w1 = (short) (e[5] ^ d5);
            w2 = (short) (e[6] ^ d6);
            w3 = (short) (e[7] ^ d7);
            b0 = (short) ((short) (w0 << 1) | (short) ((short) (w3 >> 15) & 1));
            b1 = (short) ((short) (w1 << 1) | (short) ((short) (w0 >> 15) & 1));
            b2 = (short) ((short) (w2 << 1) | (short) ((short) (w1 >> 15) & 1));
            b3 = (short) ((short) (w3 << 1) | (short) ((short) (w2 >> 15) & 1));
            w0 = (short) (e[28] ^ d8);
            w1 = (short) (e[29] ^ d9);
            w2 = (short) (e[30] ^ d10);
            w3 = (short) (e[31] ^ d11);
            b4 = (short) ((short) (w0 << 6) | (short) ((short) (w3 >> 10) & 63));
            b5 = (short) ((short) (w1 << 6) | (short) ((short) (w0 >> 10) & 63));
            b6 = (short) ((short) (w2 << 6) | (short) ((short) (w1 >> 10) & 63));
            b7 = (short) ((short) (w3 << 6) | (short) ((short) (w2 >> 10) & 63));
            w0 = (short) (e[52] ^ d12);
            w1 = (short) (e[53] ^ d13);
            w2 = (short) (e[54] ^ d14);
            w3 = (short) (e[55] ^ d15);
            b8 = (short) ((short) (w3 << 9) | (short) ((short) (w2 >> 7) & 511));
            b9 = (short) ((short) (w0 << 9) | (short) ((short) (w3 >> 7) & 511));
            b10 = (short) ((short) (w1 << 9) | (short) ((short) (w0 >> 7) & 511));
            b11 = (short) ((short) (w2 << 9) | (short) ((short) (w1 >> 7) & 511));
            w0 = (short) (e[76] ^ d16);
            w1 = (short) (e[77] ^ d17);
            w2 = (short) (e[78] ^ d18);
            w3 = (short) (e[79] ^ d19);
            b12 = (short) ((short) (w0 << 8) | (short) ((short) (w3 >> 8) & 255));
            b13 = (short) ((short) (w1 << 8) | (short) ((short) (w0 >> 8) & 255));
            b14 = (short) ((short) (w2 << 8) | (short) ((short) (w1 >> 8) & 255));
            b15 = (short) ((short) (w3 << 8) | (short) ((short) (w2 >> 8) & 255));
            w0 = (short) (e[80] ^ d0);
            w1 = (short) (e[81] ^ d1);
            w2 = (short) (e[82] ^ d2);
            w3 = (short) (e[83] ^ d3);
            b16 = (short) ((short) (w3 << 2) | (short) ((short) (w2 >> 14) & 3));
            b17 = (short) ((short) (w0 << 2) | (short) ((short) (w3 >> 14) & 3));
            b18 = (short) ((short) (w1 << 2) | (short) ((short) (w0 >> 14) & 3));
            b19 = (short) ((short) (w2 << 2) | (short) ((short) (w1 >> 14) & 3));
            a[40] = (short) (b0 ^ (short) (~b4 & b8));
            a[41] = (short) (b1 ^ (short) (~b5 & b9));
            a[42] = (short) (b2 ^ (short) (~b6 & b10));
            a[43] = (short) (b3 ^ (short) (~b7 & b11));
            a[44] = (short) (b4 ^ (short) (~b8 & b12));
            a[45] = (short) (b5 ^ (short) (~b9 & b13));
            a[46] = (short) (b6 ^ (short) (~b10 & b14));
            a[47] = (short) (b7 ^ (short) (~b11 & b15));
            a[48] = (short) (b8 ^ (short) (~b12 & b16));
            a[49] = (short) (b9 ^ (short) (~b13 & b17));
            a[50] = (short) (b10 ^ (short) (~b14 & b18));
            a[51] = (short) (b11 ^ (short) (~b15 & b19));
            a[52] = (short) (b12 ^ (short) (~b16 & b0));
            a[53] = (short) (b13 ^ (short) (~b17 & b1));
            a[54] = (short) (b14 ^ (short) (~b18 & b2));
            a[55] = (short) (b15 ^ (short) (~b19 & b3));
            a[56] = (short) (b16 ^ (short) (~b0 & b4));
            a[57] = (short) (b17 ^ (short) (~b1 & b5));
            a[58] = (short) (b18 ^ (short) (~b2 & b6));
            a[59] = (short) (b19 ^ (short) (~b3 & b7));
            w0 = (short) (e[16] ^ d16);
            w1 = (short) (e[17] ^ d17);
            w2 = (short) (e[18] ^ d18);
            w3 = (short) (e[19] ^ d19);
            b0 = (short) ((short) (w3 << 11) | (short) ((short) (w2 >> 5) & 2047));
            b1 = (short) ((short) (w0 << 11) | (short) ((short) (w3 >> 5) & 2047));
            b2 = (short) ((short) (w1 << 11) | (short) ((short) (w0 >> 5) & 2047));
            b3 = (short) ((short) (w2 << 11) | (short) ((short) (w1 >> 5) & 2047));
            w0 = (short) (e[20] ^ d0);
            w1 = (short) (e[21] ^ d1);
            w2 = (short) (e[22] ^ d2);
            w3 = (short) (e[23] ^ d3);
            b4 = (short) ((short) (w2 << 4) | (short) ((short) (w1 >> 12) & 15));
            b5 = (short) ((short) (w3 << 4) | (short) ((short) (w2 >> 12) & 15));
            b6 = (short) ((short) (w0 << 4) | (short) ((short) (w3 >> 12) & 15));
            b7 = (short) ((short) (w1 << 4) | (short) ((short) (w0 >> 12) & 15));
            w0 = (short) (e[44] ^ d4);
            w1 = (short) (e[45] ^ d5);
            w2 = (short) (e[46] ^ d6);
            w3 = (short) (e[47] ^ d7);
            b8 = (short) ((short) (w0 << 10) | (short) ((short) (w3 >> 6) & 1023));
            b9 = (short) ((short) (w1 << 10) | (short) ((short) (w0 >> 6) & 1023));
            b10 = (short) ((short) (w2 << 10) | (short) ((short) (w1 >> 6) & 1023));
            b11 = (short) ((short) (w3 << 10) | (short) ((short) (w2 >> 6) & 1023));
            w0 = (short) (e[68] ^ d8);
            w1 = (short) (e[69] ^ d9);
            w2 = (short) (e[70] ^ d10);
            w3 = (short) (e[71] ^ d11);
            b12 = (short) ((short) (w0 << 15) | (short) ((short) (w3 >> 1) & 32767));
            b13 = (short) ((short) (w1 << 15) | (short) ((short) (w0 >> 1) & 32767));
            b14 = (short) ((short) (w2 << 15) | (short) ((short) (w1 >> 1) & 32767));
            b15 = (short) ((short) (w3 << 15) | (short) ((short) (w2 >> 1) & 32767));
            w0 = (short) (e[92] ^ d12);
            w1 = (short) (e[93] ^ d13);
            w2 = (short) (e[94] ^ d14);
            w3 = (short) (e[95] ^ d15);
            b16 = (short) ((short) (w1 << 8) | (short) ((short) (w0 >> 8) & 255));
            b17 = (short) ((short) (w2 << 8) | (short) ((short) (w1 >> 8) & 255));
            b18 = (short) ((short) (w3 << 8) | (short) ((short) (w2 >> 8) & 255));
            b19 = (short) ((short) (w0 << 8) | (short) ((short) (w3 >> 8) & 255));
            a[60] = (short) (b0 ^ (short) (~b4 & b8));
            a[61] = (short) (b1 ^ (short) (~b5 & b9));
            a[62] = (short) (b2 ^ (short) (~b6 & b10));
            a[63] = (short) (b3 ^ (short) (~b7 & b11));
            a[64] = (short) (b4 ^ (short) (~b8 & b12));
            a[65] = (short) (b5 ^ (short) (~b9 & b13));
            a[66] = (short) (b6 ^ (short) (~b10 & b14));
            a[67] = (short) (b7 ^ (short) (~b11 & b15));
            a[68] = (short) (b8 ^ (short) (~b12 & b16));
            a[69] = (short) (b9 ^ (short) (~b13 & b17));
            a[70] = (short) (b10 ^ (short) (~b14 & b18));
            a[71] = (short) (b11 ^ (short) (~b15 & b19));
            a[72] = (short) (b12 ^ (short) (~b16 & b0));
            a[73] = (short) (b13 ^ (short) (~b17 & b1));
            a[74] = (short) (b14 ^ (short) (~b18 & b2));
            a[75] = (short) (b15 ^ (short) (~b19 & b3));
            a[76] = (short) (b16 ^ (short) (~b0 & b4));
            a[77] = (short) (b17 ^ (short) (~b1 & b5));
            a[78] = (short) (b18 ^ (short) (~b2 & b6));
            a[79] = (short) (b19 ^ (short) (~b3 & b7));
            w0 = (short) (e[8] ^ d8);
            w1 = (short) (e[9] ^ d9);
            w2 = (short) (e[10] ^ d10);
            w3 = (short) (e[11] ^ d11);
            b0 = (short) ((short) (w1 << 14) | (short) ((short) (w0 >> 2) & 16383));
            b1 = (short) ((short) (w2 << 14) | (short) ((short) (w1 >> 2) & 16383));
            b2 = (short) ((short) (w3 << 14) | (short) ((short) (w2 >> 2) & 16383));
            b3 = (short) ((short) (w0 << 14) | (short) ((short) (w3 >> 2) & 16383));
            w0 = (short) (e[32] ^ d12);
            w1 = (short) (e[33] ^ d13);
            w2 = (short) (e[34] ^ d14);
            w3 = (short) (e[35] ^ d15);
            b4 = (short) ((short) (w1 << 7) | (short) ((short) (w0 >> 9) & 127));
            b5 = (short) ((short) (w2 << 7) | (short) ((short) (w1 >> 9) & 127));
            b6 = (short) ((short) (w3 << 7) | (short) ((short) (w2 >> 9) & 127));
            b7 = (short) ((short) (w0 << 7) | (short) ((short) (w3 >> 9) & 127));
            w0 = (short) (e[56] ^ d16);
            w1 = (short) (e[57] ^ d17);
            w2 = (short) (e[58] ^ d18);
            w3 = (short) (e[59] ^ d19);
            b8 = (short) ((short) (w2 << 7) | (short) ((short) (w1 >> 9) & 127));
            b9 = (short) ((short) (w3 << 7) | (short) ((short) (w2 >> 9) & 127));
            b10 = (short) ((short) (w0 << 7) | (short) ((short) (w3 >> 9) & 127));
            b11 = (short) ((short) (w1 << 7) | (short) ((short) (w0 >> 9) & 127));
            w0 = (short) (e[60] ^ d0);
            w1 = (short) (e[61] ^ d1);
            w2 = (short) (e[62] ^ d2);
            w3 = (short) (e[63] ^ d3);
            b12 = (short) ((short) (w2 << 9) | (short) ((short) (w1 >> 7) & 511));
            b13 = (short) ((short) (w3 << 9) | (short) ((short) (w2 >> 7) & 511));
            b14 = (short) ((short) (w0 << 9) | (short) ((short) (w3 >> 7) & 511));
            b15 = (short) ((short) (w1 << 9) | (short) ((short) (w0 >> 7) & 511));
            w0 = (short) (e[84] ^ d4);
            w1 = (short) (e[85] ^ d5);
            w2 = (short) (e[86] ^ d6);
            w3 = (short) (e[87] ^ d7);
            b16 = (short) ((short) (w0 << 2) | (short) ((short) (w3 >> 14) & 3));
            b17 = (short) ((short) (w1 << 2) | (short) ((short) (w0 >> 14) & 3));
            b18 = (short) ((short) (w2 << 2) | (short) ((short) (w1 >> 14) & 3));
            b19 = (short) ((short) (w3 << 2) | (short) ((short) (w2 >> 14) & 3));
            a[80] = (short) (b0 ^ (short) (~b4 & b8));
            a[81] = (short) (b1 ^ (short) (~b5 & b9));
            a[82] = (short) (b2 ^ (short) (~b6 & b10));
            a[83] = (short) (b3 ^ (short) (~b7 & b11));
            a[84] = (short) (b4 ^ (short) (~b8 & b12));
            a[85] = (short) (b5 ^ (short) (~b9 & b13));
            a[86] = (short) (b6 ^ (short) (~b10 & b14));
            a[87] = (short) (b7 ^ (short) (~b11 & b15));
            a[88] = (short) (b8 ^ (short) (~b12 & b16));
            a[89] = (short) (b9 ^ (short) (~b13 & b17));
            a[90] = (short) (b10 ^ (short) (~b14 & b18));
            a[91] = (short) (b11 ^ (short) (~b15 & b19));
            a[92] = (short) (b12 ^ (short) (~b16 & b0));
            a[93] = (short) (b13 ^ (short) (~b17 & b1));
            a[94] = (short) (b14 ^ (short) (~b18 & b2));
            a[95] = (short) (b15 ^ (short) (~b19 & b3));
            a[96] = (short) (b16 ^ (short) (~b0 & b4));
            a[97] = (short) (b17 ^ (short) (~b1 & b5));
            a[98] = (short) (b18 ^ (short) (~b2 & b6));
            a[99] = (short) (b19 ^ (short) (~b3 & b7));
        }
    }

    /** SHA3-256 of a single-block message (at most 135 bytes), written to buf[0..31]. */
    private short sha3(byte[] buf, short off, short len, boolean fast) {
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
        if (fast) {
            keccakFast();
        } else {
            keccakS();
        }
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
    private void aead(boolean fast) {
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
        if (fast) {
            polyFast(mac, (short) 0, (short) 416);
        } else {
            for (j = 0; j < 416; j += 16) {
                polyBlock(j);
            }
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

    /** Poly1305 over len bytes of m (whole 16-byte blocks) with r in ph[17..33]; leaves h in ph[0..16]. */
    private void polyFast(byte[] m, short off, short len) {
        short[] p = ph;
        int r0 = p[17], r1 = p[18], r2 = p[19], r3 = p[20], r4 = p[21], r5 = p[22], r6 = p[23], r7 = p[24], r8 = p[25], r9 = p[26], r10 = p[27], r11 = p[28], r12 = p[29], r13 = p[30], r14 = p[31], r15 = p[32], r16 = p[33];
        int s1 = 320 * r1, s2 = 320 * r2, s3 = 320 * r3, s4 = 320 * r4, s5 = 320 * r5, s6 = 320 * r6, s7 = 320 * r7, s8 = 320 * r8, s9 = 320 * r9, s10 = 320 * r10, s11 = 320 * r11, s12 = 320 * r12, s13 = 320 * r13, s14 = 320 * r14, s15 = 320 * r15, s16 = 320 * r16;
        int h0 = p[0], h1 = p[1], h2 = p[2], h3 = p[3], h4 = p[4], h5 = p[5], h6 = p[6], h7 = p[7], h8 = p[8], h9 = p[9], h10 = p[10], h11 = p[11], h12 = p[12], h13 = p[13], h14 = p[14], h15 = p[15], h16 = p[16];
        int u;
        int x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15, x16;
        short end = (short) (off + len);
        for (short o = off; o < end; o += 16) {
            u = 0;
            u += h0 + (m[(short) (o + 0)] & 0xFF); h0 = u & 255; u >>>= 8;
            u += h1 + (m[(short) (o + 1)] & 0xFF); h1 = u & 255; u >>>= 8;
            u += h2 + (m[(short) (o + 2)] & 0xFF); h2 = u & 255; u >>>= 8;
            u += h3 + (m[(short) (o + 3)] & 0xFF); h3 = u & 255; u >>>= 8;
            u += h4 + (m[(short) (o + 4)] & 0xFF); h4 = u & 255; u >>>= 8;
            u += h5 + (m[(short) (o + 5)] & 0xFF); h5 = u & 255; u >>>= 8;
            u += h6 + (m[(short) (o + 6)] & 0xFF); h6 = u & 255; u >>>= 8;
            u += h7 + (m[(short) (o + 7)] & 0xFF); h7 = u & 255; u >>>= 8;
            u += h8 + (m[(short) (o + 8)] & 0xFF); h8 = u & 255; u >>>= 8;
            u += h9 + (m[(short) (o + 9)] & 0xFF); h9 = u & 255; u >>>= 8;
            u += h10 + (m[(short) (o + 10)] & 0xFF); h10 = u & 255; u >>>= 8;
            u += h11 + (m[(short) (o + 11)] & 0xFF); h11 = u & 255; u >>>= 8;
            u += h12 + (m[(short) (o + 12)] & 0xFF); h12 = u & 255; u >>>= 8;
            u += h13 + (m[(short) (o + 13)] & 0xFF); h13 = u & 255; u >>>= 8;
            u += h14 + (m[(short) (o + 14)] & 0xFF); h14 = u & 255; u >>>= 8;
            u += h15 + (m[(short) (o + 15)] & 0xFF); h15 = u & 255; u >>>= 8;
            u += h16 + 1; h16 = u & 255; u >>>= 8;
            x0 = h0 * r0 + h1 * s16 + h2 * s15 + h3 * s14 + h4 * s13 + h5 * s12 + h6 * s11 + h7 * s10 + h8 * s9 + h9 * s8 + h10 * s7 + h11 * s6 + h12 * s5 + h13 * s4 + h14 * s3 + h15 * s2 + h16 * s1;
            x1 = h0 * r1 + h1 * r0 + h2 * s16 + h3 * s15 + h4 * s14 + h5 * s13 + h6 * s12 + h7 * s11 + h8 * s10 + h9 * s9 + h10 * s8 + h11 * s7 + h12 * s6 + h13 * s5 + h14 * s4 + h15 * s3 + h16 * s2;
            x2 = h0 * r2 + h1 * r1 + h2 * r0 + h3 * s16 + h4 * s15 + h5 * s14 + h6 * s13 + h7 * s12 + h8 * s11 + h9 * s10 + h10 * s9 + h11 * s8 + h12 * s7 + h13 * s6 + h14 * s5 + h15 * s4 + h16 * s3;
            x3 = h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s16 + h5 * s15 + h6 * s14 + h7 * s13 + h8 * s12 + h9 * s11 + h10 * s10 + h11 * s9 + h12 * s8 + h13 * s7 + h14 * s6 + h15 * s5 + h16 * s4;
            x4 = h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0 + h5 * s16 + h6 * s15 + h7 * s14 + h8 * s13 + h9 * s12 + h10 * s11 + h11 * s10 + h12 * s9 + h13 * s8 + h14 * s7 + h15 * s6 + h16 * s5;
            x5 = h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1 + h5 * r0 + h6 * s16 + h7 * s15 + h8 * s14 + h9 * s13 + h10 * s12 + h11 * s11 + h12 * s10 + h13 * s9 + h14 * s8 + h15 * s7 + h16 * s6;
            x6 = h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2 + h5 * r1 + h6 * r0 + h7 * s16 + h8 * s15 + h9 * s14 + h10 * s13 + h11 * s12 + h12 * s11 + h13 * s10 + h14 * s9 + h15 * s8 + h16 * s7;
            x7 = h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3 + h5 * r2 + h6 * r1 + h7 * r0 + h8 * s16 + h9 * s15 + h10 * s14 + h11 * s13 + h12 * s12 + h13 * s11 + h14 * s10 + h15 * s9 + h16 * s8;
            x8 = h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4 + h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * s16 + h10 * s15 + h11 * s14 + h12 * s13 + h13 * s12 + h14 * s11 + h15 * s10 + h16 * s9;
            x9 = h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5 + h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0 + h10 * s16 + h11 * s15 + h12 * s14 + h13 * s13 + h14 * s12 + h15 * s11 + h16 * s10;
            x10 = h0 * r10 + h1 * r9 + h2 * r8 + h3 * r7 + h4 * r6 + h5 * r5 + h6 * r4 + h7 * r3 + h8 * r2 + h9 * r1 + h10 * r0 + h11 * s16 + h12 * s15 + h13 * s14 + h14 * s13 + h15 * s12 + h16 * s11;
            x11 = h0 * r11 + h1 * r10 + h2 * r9 + h3 * r8 + h4 * r7 + h5 * r6 + h6 * r5 + h7 * r4 + h8 * r3 + h9 * r2 + h10 * r1 + h11 * r0 + h12 * s16 + h13 * s15 + h14 * s14 + h15 * s13 + h16 * s12;
            x12 = h0 * r12 + h1 * r11 + h2 * r10 + h3 * r9 + h4 * r8 + h5 * r7 + h6 * r6 + h7 * r5 + h8 * r4 + h9 * r3 + h10 * r2 + h11 * r1 + h12 * r0 + h13 * s16 + h14 * s15 + h15 * s14 + h16 * s13;
            x13 = h0 * r13 + h1 * r12 + h2 * r11 + h3 * r10 + h4 * r9 + h5 * r8 + h6 * r7 + h7 * r6 + h8 * r5 + h9 * r4 + h10 * r3 + h11 * r2 + h12 * r1 + h13 * r0 + h14 * s16 + h15 * s15 + h16 * s14;
            x14 = h0 * r14 + h1 * r13 + h2 * r12 + h3 * r11 + h4 * r10 + h5 * r9 + h6 * r8 + h7 * r7 + h8 * r6 + h9 * r5 + h10 * r4 + h11 * r3 + h12 * r2 + h13 * r1 + h14 * r0 + h15 * s16 + h16 * s15;
            x15 = h0 * r15 + h1 * r14 + h2 * r13 + h3 * r12 + h4 * r11 + h5 * r10 + h6 * r9 + h7 * r8 + h8 * r7 + h9 * r6 + h10 * r5 + h11 * r4 + h12 * r3 + h13 * r2 + h14 * r1 + h15 * r0 + h16 * s16;
            x16 = h0 * r16 + h1 * r15 + h2 * r14 + h3 * r13 + h4 * r12 + h5 * r11 + h6 * r10 + h7 * r9 + h8 * r8 + h9 * r7 + h10 * r6 + h11 * r5 + h12 * r4 + h13 * r3 + h14 * r2 + h15 * r1 + h16 * r0;
            u = 0;
            u += x0; h0 = u & 255; u >>>= 8;
            u += x1; h1 = u & 255; u >>>= 8;
            u += x2; h2 = u & 255; u >>>= 8;
            u += x3; h3 = u & 255; u >>>= 8;
            u += x4; h4 = u & 255; u >>>= 8;
            u += x5; h5 = u & 255; u >>>= 8;
            u += x6; h6 = u & 255; u >>>= 8;
            u += x7; h7 = u & 255; u >>>= 8;
            u += x8; h8 = u & 255; u >>>= 8;
            u += x9; h9 = u & 255; u >>>= 8;
            u += x10; h10 = u & 255; u >>>= 8;
            u += x11; h11 = u & 255; u >>>= 8;
            u += x12; h12 = u & 255; u >>>= 8;
            u += x13; h13 = u & 255; u >>>= 8;
            u += x14; h14 = u & 255; u >>>= 8;
            u += x15; h15 = u & 255; u >>>= 8;
            u += x16; h16 = u & 3; u = 5 * (u >>> 2);
            u += h0; h0 = u & 255; u >>>= 8;
            u += h1; h1 = u & 255; u >>>= 8;
            u += h2; h2 = u & 255; u >>>= 8;
            u += h3; h3 = u & 255; u >>>= 8;
            u += h4; h4 = u & 255; u >>>= 8;
            u += h5; h5 = u & 255; u >>>= 8;
            u += h6; h6 = u & 255; u >>>= 8;
            u += h7; h7 = u & 255; u >>>= 8;
            u += h8; h8 = u & 255; u >>>= 8;
            u += h9; h9 = u & 255; u >>>= 8;
            u += h10; h10 = u & 255; u >>>= 8;
            u += h11; h11 = u & 255; u >>>= 8;
            u += h12; h12 = u & 255; u >>>= 8;
            u += h13; h13 = u & 255; u >>>= 8;
            u += h14; h14 = u & 255; u >>>= 8;
            u += h15; h15 = u & 255; u >>>= 8;
            u += h16; h16 = u;
        }
        p[0] = (short) h0;
        p[1] = (short) h1;
        p[2] = (short) h2;
        p[3] = (short) h3;
        p[4] = (short) h4;
        p[5] = (short) h5;
        p[6] = (short) h6;
        p[7] = (short) h7;
        p[8] = (short) h8;
        p[9] = (short) h9;
        p[10] = (short) h10;
        p[11] = (short) h11;
        p[12] = (short) h12;
        p[13] = (short) h13;
        p[14] = (short) h14;
        p[15] = (short) h15;
        p[16] = (short) h16;
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
