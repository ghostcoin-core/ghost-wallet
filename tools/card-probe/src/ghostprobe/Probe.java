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
                aeadFast();
            }
            Util.arrayCopyNonAtomic(mac, (short) 48, buf, (short) 0, (short) 16);
            Util.arrayCopyNonAtomic(blk, (short) 0, buf, (short) 16, (short) 16);
            out = 32;
            break;
        case INS_CHACHA_ONLY:
            for (i = 0; i < n; i++) {
                for (short b = 0; b < 7; b++) {
                    chachaFast(b, mac, (short) 0, (short) 64);
                }
            }
            break;
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
        // Memory first: the checks below create objects. They are unreachable
        // afterwards, so ask the card to reclaim them before the next command.
        memInfo(buf, (short) 15);
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
        if (JCSystem.isObjectDeletionSupported()) {
            JCSystem.requestObjectDeletion();
        }
        return (short) (o + 12);
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
        short[] k = ks;
        int a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15, a16, a17, a18, a19, a20, a21, a22, a23, a24, a25, a26, a27, a28, a29, a30, a31, a32, a33, a34, a35, a36, a37, a38, a39, a40, a41, a42, a43, a44, a45, a46, a47, a48, a49;
        int c0, c1, c2, c3, c4, c5, c6, c7, c8, c9;
        int d0, d1, d2, d3, d4, d5, d6, d7, d8, d9;
        int b0, b1, b2, b3, b4, b5, b6, b7, b8, b9;
        a0 = (k[1] << 16) | (k[0] & 0xFFFF);
        a1 = (k[3] << 16) | (k[2] & 0xFFFF);
        a2 = (k[5] << 16) | (k[4] & 0xFFFF);
        a3 = (k[7] << 16) | (k[6] & 0xFFFF);
        a4 = (k[9] << 16) | (k[8] & 0xFFFF);
        a5 = (k[11] << 16) | (k[10] & 0xFFFF);
        a6 = (k[13] << 16) | (k[12] & 0xFFFF);
        a7 = (k[15] << 16) | (k[14] & 0xFFFF);
        a8 = (k[17] << 16) | (k[16] & 0xFFFF);
        a9 = (k[19] << 16) | (k[18] & 0xFFFF);
        a10 = (k[21] << 16) | (k[20] & 0xFFFF);
        a11 = (k[23] << 16) | (k[22] & 0xFFFF);
        a12 = (k[25] << 16) | (k[24] & 0xFFFF);
        a13 = (k[27] << 16) | (k[26] & 0xFFFF);
        a14 = (k[29] << 16) | (k[28] & 0xFFFF);
        a15 = (k[31] << 16) | (k[30] & 0xFFFF);
        a16 = (k[33] << 16) | (k[32] & 0xFFFF);
        a17 = (k[35] << 16) | (k[34] & 0xFFFF);
        a18 = (k[37] << 16) | (k[36] & 0xFFFF);
        a19 = (k[39] << 16) | (k[38] & 0xFFFF);
        a20 = (k[41] << 16) | (k[40] & 0xFFFF);
        a21 = (k[43] << 16) | (k[42] & 0xFFFF);
        a22 = (k[45] << 16) | (k[44] & 0xFFFF);
        a23 = (k[47] << 16) | (k[46] & 0xFFFF);
        a24 = (k[49] << 16) | (k[48] & 0xFFFF);
        a25 = (k[51] << 16) | (k[50] & 0xFFFF);
        a26 = (k[53] << 16) | (k[52] & 0xFFFF);
        a27 = (k[55] << 16) | (k[54] & 0xFFFF);
        a28 = (k[57] << 16) | (k[56] & 0xFFFF);
        a29 = (k[59] << 16) | (k[58] & 0xFFFF);
        a30 = (k[61] << 16) | (k[60] & 0xFFFF);
        a31 = (k[63] << 16) | (k[62] & 0xFFFF);
        a32 = (k[65] << 16) | (k[64] & 0xFFFF);
        a33 = (k[67] << 16) | (k[66] & 0xFFFF);
        a34 = (k[69] << 16) | (k[68] & 0xFFFF);
        a35 = (k[71] << 16) | (k[70] & 0xFFFF);
        a36 = (k[73] << 16) | (k[72] & 0xFFFF);
        a37 = (k[75] << 16) | (k[74] & 0xFFFF);
        a38 = (k[77] << 16) | (k[76] & 0xFFFF);
        a39 = (k[79] << 16) | (k[78] & 0xFFFF);
        a40 = (k[81] << 16) | (k[80] & 0xFFFF);
        a41 = (k[83] << 16) | (k[82] & 0xFFFF);
        a42 = (k[85] << 16) | (k[84] & 0xFFFF);
        a43 = (k[87] << 16) | (k[86] & 0xFFFF);
        a44 = (k[89] << 16) | (k[88] & 0xFFFF);
        a45 = (k[91] << 16) | (k[90] & 0xFFFF);
        a46 = (k[93] << 16) | (k[92] & 0xFFFF);
        a47 = (k[95] << 16) | (k[94] & 0xFFFF);
        a48 = (k[97] << 16) | (k[96] & 0xFFFF);
        a49 = (k[99] << 16) | (k[98] & 0xFFFF);
        for (short r = 0; r < 96; r += 16) {
            c0 = a0 ^ a10 ^ a20 ^ a30 ^ a40;
            c1 = a1 ^ a11 ^ a21 ^ a31 ^ a41;
            c2 = a2 ^ a12 ^ a22 ^ a32 ^ a42;
            c3 = a3 ^ a13 ^ a23 ^ a33 ^ a43;
            c4 = a4 ^ a14 ^ a24 ^ a34 ^ a44;
            c5 = a5 ^ a15 ^ a25 ^ a35 ^ a45;
            c6 = a6 ^ a16 ^ a26 ^ a36 ^ a46;
            c7 = a7 ^ a17 ^ a27 ^ a37 ^ a47;
            c8 = a8 ^ a18 ^ a28 ^ a38 ^ a48;
            c9 = a9 ^ a19 ^ a29 ^ a39 ^ a49;
            d0 = c8 ^ ((c2 << 1) | (c3 >>> 31));
            d1 = c9 ^ ((c3 << 1) | (c2 >>> 31));
            d2 = c0 ^ ((c4 << 1) | (c5 >>> 31));
            d3 = c1 ^ ((c5 << 1) | (c4 >>> 31));
            d4 = c2 ^ ((c6 << 1) | (c7 >>> 31));
            d5 = c3 ^ ((c7 << 1) | (c6 >>> 31));
            d6 = c4 ^ ((c8 << 1) | (c9 >>> 31));
            d7 = c5 ^ ((c9 << 1) | (c8 >>> 31));
            d8 = c6 ^ ((c0 << 1) | (c1 >>> 31));
            d9 = c7 ^ ((c1 << 1) | (c0 >>> 31));
            b0 = (a0 ^ d0);
            b1 = (a1 ^ d1);
            b2 = ((a13 ^ d3) << 12) | ((a12 ^ d2) >>> 20);
            b3 = ((a12 ^ d2) << 12) | ((a13 ^ d3) >>> 20);
            b4 = ((a25 ^ d5) << 11) | ((a24 ^ d4) >>> 21);
            b5 = ((a24 ^ d4) << 11) | ((a25 ^ d5) >>> 21);
            b6 = ((a36 ^ d6) << 21) | ((a37 ^ d7) >>> 11);
            b7 = ((a37 ^ d7) << 21) | ((a36 ^ d6) >>> 11);
            b8 = ((a48 ^ d8) << 14) | ((a49 ^ d9) >>> 18);
            b9 = ((a49 ^ d9) << 14) | ((a48 ^ d8) >>> 18);
            a0 = b0 ^ (~b2 & b4) ^ ((RCS[(short) (r + 1)] << 16) | (RCS[(short) (r + 0)] & 0xFFFF));
            a1 = b1 ^ (~b3 & b5) ^ ((RCS[(short) (r + 3)] << 16) | (RCS[(short) (r + 2)] & 0xFFFF));
            a12 = b2 ^ (~b4 & b6);
            a13 = b3 ^ (~b5 & b7);
            a24 = b4 ^ (~b6 & b8);
            a25 = b5 ^ (~b7 & b9);
            a36 = b6 ^ (~b8 & b0);
            a37 = b7 ^ (~b9 & b1);
            a48 = b8 ^ (~b0 & b2);
            a49 = b9 ^ (~b1 & b3);
            b0 = ((a6 ^ d6) << 28) | ((a7 ^ d7) >>> 4);
            b1 = ((a7 ^ d7) << 28) | ((a6 ^ d6) >>> 4);
            b2 = ((a18 ^ d8) << 20) | ((a19 ^ d9) >>> 12);
            b3 = ((a19 ^ d9) << 20) | ((a18 ^ d8) >>> 12);
            b4 = ((a20 ^ d0) << 3) | ((a21 ^ d1) >>> 29);
            b5 = ((a21 ^ d1) << 3) | ((a20 ^ d0) >>> 29);
            b6 = ((a33 ^ d3) << 13) | ((a32 ^ d2) >>> 19);
            b7 = ((a32 ^ d2) << 13) | ((a33 ^ d3) >>> 19);
            b8 = ((a45 ^ d5) << 29) | ((a44 ^ d4) >>> 3);
            b9 = ((a44 ^ d4) << 29) | ((a45 ^ d5) >>> 3);
            a20 = b0 ^ (~b2 & b4);
            a21 = b1 ^ (~b3 & b5);
            a32 = b2 ^ (~b4 & b6);
            a33 = b3 ^ (~b5 & b7);
            a44 = b4 ^ (~b6 & b8);
            a45 = b5 ^ (~b7 & b9);
            a6 = b6 ^ (~b8 & b0);
            a7 = b7 ^ (~b9 & b1);
            a18 = b8 ^ (~b0 & b2);
            a19 = b9 ^ (~b1 & b3);
            b0 = ((a2 ^ d2) << 1) | ((a3 ^ d3) >>> 31);
            b1 = ((a3 ^ d3) << 1) | ((a2 ^ d2) >>> 31);
            b2 = ((a14 ^ d4) << 6) | ((a15 ^ d5) >>> 26);
            b3 = ((a15 ^ d5) << 6) | ((a14 ^ d4) >>> 26);
            b4 = ((a26 ^ d6) << 25) | ((a27 ^ d7) >>> 7);
            b5 = ((a27 ^ d7) << 25) | ((a26 ^ d6) >>> 7);
            b6 = ((a38 ^ d8) << 8) | ((a39 ^ d9) >>> 24);
            b7 = ((a39 ^ d9) << 8) | ((a38 ^ d8) >>> 24);
            b8 = ((a40 ^ d0) << 18) | ((a41 ^ d1) >>> 14);
            b9 = ((a41 ^ d1) << 18) | ((a40 ^ d0) >>> 14);
            a40 = b0 ^ (~b2 & b4);
            a41 = b1 ^ (~b3 & b5);
            a2 = b2 ^ (~b4 & b6);
            a3 = b3 ^ (~b5 & b7);
            a14 = b4 ^ (~b6 & b8);
            a15 = b5 ^ (~b7 & b9);
            a26 = b6 ^ (~b8 & b0);
            a27 = b7 ^ (~b9 & b1);
            a38 = b8 ^ (~b0 & b2);
            a39 = b9 ^ (~b1 & b3);
            b0 = ((a8 ^ d8) << 27) | ((a9 ^ d9) >>> 5);
            b1 = ((a9 ^ d9) << 27) | ((a8 ^ d8) >>> 5);
            b2 = ((a11 ^ d1) << 4) | ((a10 ^ d0) >>> 28);
            b3 = ((a10 ^ d0) << 4) | ((a11 ^ d1) >>> 28);
            b4 = ((a22 ^ d2) << 10) | ((a23 ^ d3) >>> 22);
            b5 = ((a23 ^ d3) << 10) | ((a22 ^ d2) >>> 22);
            b6 = ((a34 ^ d4) << 15) | ((a35 ^ d5) >>> 17);
            b7 = ((a35 ^ d5) << 15) | ((a34 ^ d4) >>> 17);
            b8 = ((a47 ^ d7) << 24) | ((a46 ^ d6) >>> 8);
            b9 = ((a46 ^ d6) << 24) | ((a47 ^ d7) >>> 8);
            a10 = b0 ^ (~b2 & b4);
            a11 = b1 ^ (~b3 & b5);
            a22 = b2 ^ (~b4 & b6);
            a23 = b3 ^ (~b5 & b7);
            a34 = b4 ^ (~b6 & b8);
            a35 = b5 ^ (~b7 & b9);
            a46 = b6 ^ (~b8 & b0);
            a47 = b7 ^ (~b9 & b1);
            a8 = b8 ^ (~b0 & b2);
            a9 = b9 ^ (~b1 & b3);
            b0 = ((a5 ^ d5) << 30) | ((a4 ^ d4) >>> 2);
            b1 = ((a4 ^ d4) << 30) | ((a5 ^ d5) >>> 2);
            b2 = ((a17 ^ d7) << 23) | ((a16 ^ d6) >>> 9);
            b3 = ((a16 ^ d6) << 23) | ((a17 ^ d7) >>> 9);
            b4 = ((a29 ^ d9) << 7) | ((a28 ^ d8) >>> 25);
            b5 = ((a28 ^ d8) << 7) | ((a29 ^ d9) >>> 25);
            b6 = ((a31 ^ d1) << 9) | ((a30 ^ d0) >>> 23);
            b7 = ((a30 ^ d0) << 9) | ((a31 ^ d1) >>> 23);
            b8 = ((a42 ^ d2) << 2) | ((a43 ^ d3) >>> 30);
            b9 = ((a43 ^ d3) << 2) | ((a42 ^ d2) >>> 30);
            a30 = b0 ^ (~b2 & b4);
            a31 = b1 ^ (~b3 & b5);
            a42 = b2 ^ (~b4 & b6);
            a43 = b3 ^ (~b5 & b7);
            a4 = b4 ^ (~b6 & b8);
            a5 = b5 ^ (~b7 & b9);
            a16 = b6 ^ (~b8 & b0);
            a17 = b7 ^ (~b9 & b1);
            a28 = b8 ^ (~b0 & b2);
            a29 = b9 ^ (~b1 & b3);
            c0 = a0 ^ a20 ^ a40 ^ a10 ^ a30;
            c1 = a1 ^ a21 ^ a41 ^ a11 ^ a31;
            c2 = a12 ^ a32 ^ a2 ^ a22 ^ a42;
            c3 = a13 ^ a33 ^ a3 ^ a23 ^ a43;
            c4 = a24 ^ a44 ^ a14 ^ a34 ^ a4;
            c5 = a25 ^ a45 ^ a15 ^ a35 ^ a5;
            c6 = a36 ^ a6 ^ a26 ^ a46 ^ a16;
            c7 = a37 ^ a7 ^ a27 ^ a47 ^ a17;
            c8 = a48 ^ a18 ^ a38 ^ a8 ^ a28;
            c9 = a49 ^ a19 ^ a39 ^ a9 ^ a29;
            d0 = c8 ^ ((c2 << 1) | (c3 >>> 31));
            d1 = c9 ^ ((c3 << 1) | (c2 >>> 31));
            d2 = c0 ^ ((c4 << 1) | (c5 >>> 31));
            d3 = c1 ^ ((c5 << 1) | (c4 >>> 31));
            d4 = c2 ^ ((c6 << 1) | (c7 >>> 31));
            d5 = c3 ^ ((c7 << 1) | (c6 >>> 31));
            d6 = c4 ^ ((c8 << 1) | (c9 >>> 31));
            d7 = c5 ^ ((c9 << 1) | (c8 >>> 31));
            d8 = c6 ^ ((c0 << 1) | (c1 >>> 31));
            d9 = c7 ^ ((c1 << 1) | (c0 >>> 31));
            b0 = (a0 ^ d0);
            b1 = (a1 ^ d1);
            b2 = ((a33 ^ d3) << 12) | ((a32 ^ d2) >>> 20);
            b3 = ((a32 ^ d2) << 12) | ((a33 ^ d3) >>> 20);
            b4 = ((a15 ^ d5) << 11) | ((a14 ^ d4) >>> 21);
            b5 = ((a14 ^ d4) << 11) | ((a15 ^ d5) >>> 21);
            b6 = ((a46 ^ d6) << 21) | ((a47 ^ d7) >>> 11);
            b7 = ((a47 ^ d7) << 21) | ((a46 ^ d6) >>> 11);
            b8 = ((a28 ^ d8) << 14) | ((a29 ^ d9) >>> 18);
            b9 = ((a29 ^ d9) << 14) | ((a28 ^ d8) >>> 18);
            a0 = b0 ^ (~b2 & b4) ^ ((RCS[(short) (r + 4 + 1)] << 16) | (RCS[(short) (r + 4 + 0)] & 0xFFFF));
            a1 = b1 ^ (~b3 & b5) ^ ((RCS[(short) (r + 4 + 3)] << 16) | (RCS[(short) (r + 4 + 2)] & 0xFFFF));
            a32 = b2 ^ (~b4 & b6);
            a33 = b3 ^ (~b5 & b7);
            a14 = b4 ^ (~b6 & b8);
            a15 = b5 ^ (~b7 & b9);
            a46 = b6 ^ (~b8 & b0);
            a47 = b7 ^ (~b9 & b1);
            a28 = b8 ^ (~b0 & b2);
            a29 = b9 ^ (~b1 & b3);
            b0 = ((a36 ^ d6) << 28) | ((a37 ^ d7) >>> 4);
            b1 = ((a37 ^ d7) << 28) | ((a36 ^ d6) >>> 4);
            b2 = ((a18 ^ d8) << 20) | ((a19 ^ d9) >>> 12);
            b3 = ((a19 ^ d9) << 20) | ((a18 ^ d8) >>> 12);
            b4 = ((a40 ^ d0) << 3) | ((a41 ^ d1) >>> 29);
            b5 = ((a41 ^ d1) << 3) | ((a40 ^ d0) >>> 29);
            b6 = ((a23 ^ d3) << 13) | ((a22 ^ d2) >>> 19);
            b7 = ((a22 ^ d2) << 13) | ((a23 ^ d3) >>> 19);
            b8 = ((a5 ^ d5) << 29) | ((a4 ^ d4) >>> 3);
            b9 = ((a4 ^ d4) << 29) | ((a5 ^ d5) >>> 3);
            a40 = b0 ^ (~b2 & b4);
            a41 = b1 ^ (~b3 & b5);
            a22 = b2 ^ (~b4 & b6);
            a23 = b3 ^ (~b5 & b7);
            a4 = b4 ^ (~b6 & b8);
            a5 = b5 ^ (~b7 & b9);
            a36 = b6 ^ (~b8 & b0);
            a37 = b7 ^ (~b9 & b1);
            a18 = b8 ^ (~b0 & b2);
            a19 = b9 ^ (~b1 & b3);
            b0 = ((a12 ^ d2) << 1) | ((a13 ^ d3) >>> 31);
            b1 = ((a13 ^ d3) << 1) | ((a12 ^ d2) >>> 31);
            b2 = ((a44 ^ d4) << 6) | ((a45 ^ d5) >>> 26);
            b3 = ((a45 ^ d5) << 6) | ((a44 ^ d4) >>> 26);
            b4 = ((a26 ^ d6) << 25) | ((a27 ^ d7) >>> 7);
            b5 = ((a27 ^ d7) << 25) | ((a26 ^ d6) >>> 7);
            b6 = ((a8 ^ d8) << 8) | ((a9 ^ d9) >>> 24);
            b7 = ((a9 ^ d9) << 8) | ((a8 ^ d8) >>> 24);
            b8 = ((a30 ^ d0) << 18) | ((a31 ^ d1) >>> 14);
            b9 = ((a31 ^ d1) << 18) | ((a30 ^ d0) >>> 14);
            a30 = b0 ^ (~b2 & b4);
            a31 = b1 ^ (~b3 & b5);
            a12 = b2 ^ (~b4 & b6);
            a13 = b3 ^ (~b5 & b7);
            a44 = b4 ^ (~b6 & b8);
            a45 = b5 ^ (~b7 & b9);
            a26 = b6 ^ (~b8 & b0);
            a27 = b7 ^ (~b9 & b1);
            a8 = b8 ^ (~b0 & b2);
            a9 = b9 ^ (~b1 & b3);
            b0 = ((a48 ^ d8) << 27) | ((a49 ^ d9) >>> 5);
            b1 = ((a49 ^ d9) << 27) | ((a48 ^ d8) >>> 5);
            b2 = ((a21 ^ d1) << 4) | ((a20 ^ d0) >>> 28);
            b3 = ((a20 ^ d0) << 4) | ((a21 ^ d1) >>> 28);
            b4 = ((a2 ^ d2) << 10) | ((a3 ^ d3) >>> 22);
            b5 = ((a3 ^ d3) << 10) | ((a2 ^ d2) >>> 22);
            b6 = ((a34 ^ d4) << 15) | ((a35 ^ d5) >>> 17);
            b7 = ((a35 ^ d5) << 15) | ((a34 ^ d4) >>> 17);
            b8 = ((a17 ^ d7) << 24) | ((a16 ^ d6) >>> 8);
            b9 = ((a16 ^ d6) << 24) | ((a17 ^ d7) >>> 8);
            a20 = b0 ^ (~b2 & b4);
            a21 = b1 ^ (~b3 & b5);
            a2 = b2 ^ (~b4 & b6);
            a3 = b3 ^ (~b5 & b7);
            a34 = b4 ^ (~b6 & b8);
            a35 = b5 ^ (~b7 & b9);
            a16 = b6 ^ (~b8 & b0);
            a17 = b7 ^ (~b9 & b1);
            a48 = b8 ^ (~b0 & b2);
            a49 = b9 ^ (~b1 & b3);
            b0 = ((a25 ^ d5) << 30) | ((a24 ^ d4) >>> 2);
            b1 = ((a24 ^ d4) << 30) | ((a25 ^ d5) >>> 2);
            b2 = ((a7 ^ d7) << 23) | ((a6 ^ d6) >>> 9);
            b3 = ((a6 ^ d6) << 23) | ((a7 ^ d7) >>> 9);
            b4 = ((a39 ^ d9) << 7) | ((a38 ^ d8) >>> 25);
            b5 = ((a38 ^ d8) << 7) | ((a39 ^ d9) >>> 25);
            b6 = ((a11 ^ d1) << 9) | ((a10 ^ d0) >>> 23);
            b7 = ((a10 ^ d0) << 9) | ((a11 ^ d1) >>> 23);
            b8 = ((a42 ^ d2) << 2) | ((a43 ^ d3) >>> 30);
            b9 = ((a43 ^ d3) << 2) | ((a42 ^ d2) >>> 30);
            a10 = b0 ^ (~b2 & b4);
            a11 = b1 ^ (~b3 & b5);
            a42 = b2 ^ (~b4 & b6);
            a43 = b3 ^ (~b5 & b7);
            a24 = b4 ^ (~b6 & b8);
            a25 = b5 ^ (~b7 & b9);
            a6 = b6 ^ (~b8 & b0);
            a7 = b7 ^ (~b9 & b1);
            a38 = b8 ^ (~b0 & b2);
            a39 = b9 ^ (~b1 & b3);
            c0 = a0 ^ a40 ^ a30 ^ a20 ^ a10;
            c1 = a1 ^ a41 ^ a31 ^ a21 ^ a11;
            c2 = a32 ^ a22 ^ a12 ^ a2 ^ a42;
            c3 = a33 ^ a23 ^ a13 ^ a3 ^ a43;
            c4 = a14 ^ a4 ^ a44 ^ a34 ^ a24;
            c5 = a15 ^ a5 ^ a45 ^ a35 ^ a25;
            c6 = a46 ^ a36 ^ a26 ^ a16 ^ a6;
            c7 = a47 ^ a37 ^ a27 ^ a17 ^ a7;
            c8 = a28 ^ a18 ^ a8 ^ a48 ^ a38;
            c9 = a29 ^ a19 ^ a9 ^ a49 ^ a39;
            d0 = c8 ^ ((c2 << 1) | (c3 >>> 31));
            d1 = c9 ^ ((c3 << 1) | (c2 >>> 31));
            d2 = c0 ^ ((c4 << 1) | (c5 >>> 31));
            d3 = c1 ^ ((c5 << 1) | (c4 >>> 31));
            d4 = c2 ^ ((c6 << 1) | (c7 >>> 31));
            d5 = c3 ^ ((c7 << 1) | (c6 >>> 31));
            d6 = c4 ^ ((c8 << 1) | (c9 >>> 31));
            d7 = c5 ^ ((c9 << 1) | (c8 >>> 31));
            d8 = c6 ^ ((c0 << 1) | (c1 >>> 31));
            d9 = c7 ^ ((c1 << 1) | (c0 >>> 31));
            b0 = (a0 ^ d0);
            b1 = (a1 ^ d1);
            b2 = ((a23 ^ d3) << 12) | ((a22 ^ d2) >>> 20);
            b3 = ((a22 ^ d2) << 12) | ((a23 ^ d3) >>> 20);
            b4 = ((a45 ^ d5) << 11) | ((a44 ^ d4) >>> 21);
            b5 = ((a44 ^ d4) << 11) | ((a45 ^ d5) >>> 21);
            b6 = ((a16 ^ d6) << 21) | ((a17 ^ d7) >>> 11);
            b7 = ((a17 ^ d7) << 21) | ((a16 ^ d6) >>> 11);
            b8 = ((a38 ^ d8) << 14) | ((a39 ^ d9) >>> 18);
            b9 = ((a39 ^ d9) << 14) | ((a38 ^ d8) >>> 18);
            a0 = b0 ^ (~b2 & b4) ^ ((RCS[(short) (r + 8 + 1)] << 16) | (RCS[(short) (r + 8 + 0)] & 0xFFFF));
            a1 = b1 ^ (~b3 & b5) ^ ((RCS[(short) (r + 8 + 3)] << 16) | (RCS[(short) (r + 8 + 2)] & 0xFFFF));
            a22 = b2 ^ (~b4 & b6);
            a23 = b3 ^ (~b5 & b7);
            a44 = b4 ^ (~b6 & b8);
            a45 = b5 ^ (~b7 & b9);
            a16 = b6 ^ (~b8 & b0);
            a17 = b7 ^ (~b9 & b1);
            a38 = b8 ^ (~b0 & b2);
            a39 = b9 ^ (~b1 & b3);
            b0 = ((a46 ^ d6) << 28) | ((a47 ^ d7) >>> 4);
            b1 = ((a47 ^ d7) << 28) | ((a46 ^ d6) >>> 4);
            b2 = ((a18 ^ d8) << 20) | ((a19 ^ d9) >>> 12);
            b3 = ((a19 ^ d9) << 20) | ((a18 ^ d8) >>> 12);
            b4 = ((a30 ^ d0) << 3) | ((a31 ^ d1) >>> 29);
            b5 = ((a31 ^ d1) << 3) | ((a30 ^ d0) >>> 29);
            b6 = ((a3 ^ d3) << 13) | ((a2 ^ d2) >>> 19);
            b7 = ((a2 ^ d2) << 13) | ((a3 ^ d3) >>> 19);
            b8 = ((a25 ^ d5) << 29) | ((a24 ^ d4) >>> 3);
            b9 = ((a24 ^ d4) << 29) | ((a25 ^ d5) >>> 3);
            a30 = b0 ^ (~b2 & b4);
            a31 = b1 ^ (~b3 & b5);
            a2 = b2 ^ (~b4 & b6);
            a3 = b3 ^ (~b5 & b7);
            a24 = b4 ^ (~b6 & b8);
            a25 = b5 ^ (~b7 & b9);
            a46 = b6 ^ (~b8 & b0);
            a47 = b7 ^ (~b9 & b1);
            a18 = b8 ^ (~b0 & b2);
            a19 = b9 ^ (~b1 & b3);
            b0 = ((a32 ^ d2) << 1) | ((a33 ^ d3) >>> 31);
            b1 = ((a33 ^ d3) << 1) | ((a32 ^ d2) >>> 31);
            b2 = ((a4 ^ d4) << 6) | ((a5 ^ d5) >>> 26);
            b3 = ((a5 ^ d5) << 6) | ((a4 ^ d4) >>> 26);
            b4 = ((a26 ^ d6) << 25) | ((a27 ^ d7) >>> 7);
            b5 = ((a27 ^ d7) << 25) | ((a26 ^ d6) >>> 7);
            b6 = ((a48 ^ d8) << 8) | ((a49 ^ d9) >>> 24);
            b7 = ((a49 ^ d9) << 8) | ((a48 ^ d8) >>> 24);
            b8 = ((a10 ^ d0) << 18) | ((a11 ^ d1) >>> 14);
            b9 = ((a11 ^ d1) << 18) | ((a10 ^ d0) >>> 14);
            a10 = b0 ^ (~b2 & b4);
            a11 = b1 ^ (~b3 & b5);
            a32 = b2 ^ (~b4 & b6);
            a33 = b3 ^ (~b5 & b7);
            a4 = b4 ^ (~b6 & b8);
            a5 = b5 ^ (~b7 & b9);
            a26 = b6 ^ (~b8 & b0);
            a27 = b7 ^ (~b9 & b1);
            a48 = b8 ^ (~b0 & b2);
            a49 = b9 ^ (~b1 & b3);
            b0 = ((a28 ^ d8) << 27) | ((a29 ^ d9) >>> 5);
            b1 = ((a29 ^ d9) << 27) | ((a28 ^ d8) >>> 5);
            b2 = ((a41 ^ d1) << 4) | ((a40 ^ d0) >>> 28);
            b3 = ((a40 ^ d0) << 4) | ((a41 ^ d1) >>> 28);
            b4 = ((a12 ^ d2) << 10) | ((a13 ^ d3) >>> 22);
            b5 = ((a13 ^ d3) << 10) | ((a12 ^ d2) >>> 22);
            b6 = ((a34 ^ d4) << 15) | ((a35 ^ d5) >>> 17);
            b7 = ((a35 ^ d5) << 15) | ((a34 ^ d4) >>> 17);
            b8 = ((a7 ^ d7) << 24) | ((a6 ^ d6) >>> 8);
            b9 = ((a6 ^ d6) << 24) | ((a7 ^ d7) >>> 8);
            a40 = b0 ^ (~b2 & b4);
            a41 = b1 ^ (~b3 & b5);
            a12 = b2 ^ (~b4 & b6);
            a13 = b3 ^ (~b5 & b7);
            a34 = b4 ^ (~b6 & b8);
            a35 = b5 ^ (~b7 & b9);
            a6 = b6 ^ (~b8 & b0);
            a7 = b7 ^ (~b9 & b1);
            a28 = b8 ^ (~b0 & b2);
            a29 = b9 ^ (~b1 & b3);
            b0 = ((a15 ^ d5) << 30) | ((a14 ^ d4) >>> 2);
            b1 = ((a14 ^ d4) << 30) | ((a15 ^ d5) >>> 2);
            b2 = ((a37 ^ d7) << 23) | ((a36 ^ d6) >>> 9);
            b3 = ((a36 ^ d6) << 23) | ((a37 ^ d7) >>> 9);
            b4 = ((a9 ^ d9) << 7) | ((a8 ^ d8) >>> 25);
            b5 = ((a8 ^ d8) << 7) | ((a9 ^ d9) >>> 25);
            b6 = ((a21 ^ d1) << 9) | ((a20 ^ d0) >>> 23);
            b7 = ((a20 ^ d0) << 9) | ((a21 ^ d1) >>> 23);
            b8 = ((a42 ^ d2) << 2) | ((a43 ^ d3) >>> 30);
            b9 = ((a43 ^ d3) << 2) | ((a42 ^ d2) >>> 30);
            a20 = b0 ^ (~b2 & b4);
            a21 = b1 ^ (~b3 & b5);
            a42 = b2 ^ (~b4 & b6);
            a43 = b3 ^ (~b5 & b7);
            a14 = b4 ^ (~b6 & b8);
            a15 = b5 ^ (~b7 & b9);
            a36 = b6 ^ (~b8 & b0);
            a37 = b7 ^ (~b9 & b1);
            a8 = b8 ^ (~b0 & b2);
            a9 = b9 ^ (~b1 & b3);
            c0 = a0 ^ a30 ^ a10 ^ a40 ^ a20;
            c1 = a1 ^ a31 ^ a11 ^ a41 ^ a21;
            c2 = a22 ^ a2 ^ a32 ^ a12 ^ a42;
            c3 = a23 ^ a3 ^ a33 ^ a13 ^ a43;
            c4 = a44 ^ a24 ^ a4 ^ a34 ^ a14;
            c5 = a45 ^ a25 ^ a5 ^ a35 ^ a15;
            c6 = a16 ^ a46 ^ a26 ^ a6 ^ a36;
            c7 = a17 ^ a47 ^ a27 ^ a7 ^ a37;
            c8 = a38 ^ a18 ^ a48 ^ a28 ^ a8;
            c9 = a39 ^ a19 ^ a49 ^ a29 ^ a9;
            d0 = c8 ^ ((c2 << 1) | (c3 >>> 31));
            d1 = c9 ^ ((c3 << 1) | (c2 >>> 31));
            d2 = c0 ^ ((c4 << 1) | (c5 >>> 31));
            d3 = c1 ^ ((c5 << 1) | (c4 >>> 31));
            d4 = c2 ^ ((c6 << 1) | (c7 >>> 31));
            d5 = c3 ^ ((c7 << 1) | (c6 >>> 31));
            d6 = c4 ^ ((c8 << 1) | (c9 >>> 31));
            d7 = c5 ^ ((c9 << 1) | (c8 >>> 31));
            d8 = c6 ^ ((c0 << 1) | (c1 >>> 31));
            d9 = c7 ^ ((c1 << 1) | (c0 >>> 31));
            b0 = (a0 ^ d0);
            b1 = (a1 ^ d1);
            b2 = ((a3 ^ d3) << 12) | ((a2 ^ d2) >>> 20);
            b3 = ((a2 ^ d2) << 12) | ((a3 ^ d3) >>> 20);
            b4 = ((a5 ^ d5) << 11) | ((a4 ^ d4) >>> 21);
            b5 = ((a4 ^ d4) << 11) | ((a5 ^ d5) >>> 21);
            b6 = ((a6 ^ d6) << 21) | ((a7 ^ d7) >>> 11);
            b7 = ((a7 ^ d7) << 21) | ((a6 ^ d6) >>> 11);
            b8 = ((a8 ^ d8) << 14) | ((a9 ^ d9) >>> 18);
            b9 = ((a9 ^ d9) << 14) | ((a8 ^ d8) >>> 18);
            a0 = b0 ^ (~b2 & b4) ^ ((RCS[(short) (r + 12 + 1)] << 16) | (RCS[(short) (r + 12 + 0)] & 0xFFFF));
            a1 = b1 ^ (~b3 & b5) ^ ((RCS[(short) (r + 12 + 3)] << 16) | (RCS[(short) (r + 12 + 2)] & 0xFFFF));
            a2 = b2 ^ (~b4 & b6);
            a3 = b3 ^ (~b5 & b7);
            a4 = b4 ^ (~b6 & b8);
            a5 = b5 ^ (~b7 & b9);
            a6 = b6 ^ (~b8 & b0);
            a7 = b7 ^ (~b9 & b1);
            a8 = b8 ^ (~b0 & b2);
            a9 = b9 ^ (~b1 & b3);
            b0 = ((a16 ^ d6) << 28) | ((a17 ^ d7) >>> 4);
            b1 = ((a17 ^ d7) << 28) | ((a16 ^ d6) >>> 4);
            b2 = ((a18 ^ d8) << 20) | ((a19 ^ d9) >>> 12);
            b3 = ((a19 ^ d9) << 20) | ((a18 ^ d8) >>> 12);
            b4 = ((a10 ^ d0) << 3) | ((a11 ^ d1) >>> 29);
            b5 = ((a11 ^ d1) << 3) | ((a10 ^ d0) >>> 29);
            b6 = ((a13 ^ d3) << 13) | ((a12 ^ d2) >>> 19);
            b7 = ((a12 ^ d2) << 13) | ((a13 ^ d3) >>> 19);
            b8 = ((a15 ^ d5) << 29) | ((a14 ^ d4) >>> 3);
            b9 = ((a14 ^ d4) << 29) | ((a15 ^ d5) >>> 3);
            a10 = b0 ^ (~b2 & b4);
            a11 = b1 ^ (~b3 & b5);
            a12 = b2 ^ (~b4 & b6);
            a13 = b3 ^ (~b5 & b7);
            a14 = b4 ^ (~b6 & b8);
            a15 = b5 ^ (~b7 & b9);
            a16 = b6 ^ (~b8 & b0);
            a17 = b7 ^ (~b9 & b1);
            a18 = b8 ^ (~b0 & b2);
            a19 = b9 ^ (~b1 & b3);
            b0 = ((a22 ^ d2) << 1) | ((a23 ^ d3) >>> 31);
            b1 = ((a23 ^ d3) << 1) | ((a22 ^ d2) >>> 31);
            b2 = ((a24 ^ d4) << 6) | ((a25 ^ d5) >>> 26);
            b3 = ((a25 ^ d5) << 6) | ((a24 ^ d4) >>> 26);
            b4 = ((a26 ^ d6) << 25) | ((a27 ^ d7) >>> 7);
            b5 = ((a27 ^ d7) << 25) | ((a26 ^ d6) >>> 7);
            b6 = ((a28 ^ d8) << 8) | ((a29 ^ d9) >>> 24);
            b7 = ((a29 ^ d9) << 8) | ((a28 ^ d8) >>> 24);
            b8 = ((a20 ^ d0) << 18) | ((a21 ^ d1) >>> 14);
            b9 = ((a21 ^ d1) << 18) | ((a20 ^ d0) >>> 14);
            a20 = b0 ^ (~b2 & b4);
            a21 = b1 ^ (~b3 & b5);
            a22 = b2 ^ (~b4 & b6);
            a23 = b3 ^ (~b5 & b7);
            a24 = b4 ^ (~b6 & b8);
            a25 = b5 ^ (~b7 & b9);
            a26 = b6 ^ (~b8 & b0);
            a27 = b7 ^ (~b9 & b1);
            a28 = b8 ^ (~b0 & b2);
            a29 = b9 ^ (~b1 & b3);
            b0 = ((a38 ^ d8) << 27) | ((a39 ^ d9) >>> 5);
            b1 = ((a39 ^ d9) << 27) | ((a38 ^ d8) >>> 5);
            b2 = ((a31 ^ d1) << 4) | ((a30 ^ d0) >>> 28);
            b3 = ((a30 ^ d0) << 4) | ((a31 ^ d1) >>> 28);
            b4 = ((a32 ^ d2) << 10) | ((a33 ^ d3) >>> 22);
            b5 = ((a33 ^ d3) << 10) | ((a32 ^ d2) >>> 22);
            b6 = ((a34 ^ d4) << 15) | ((a35 ^ d5) >>> 17);
            b7 = ((a35 ^ d5) << 15) | ((a34 ^ d4) >>> 17);
            b8 = ((a37 ^ d7) << 24) | ((a36 ^ d6) >>> 8);
            b9 = ((a36 ^ d6) << 24) | ((a37 ^ d7) >>> 8);
            a30 = b0 ^ (~b2 & b4);
            a31 = b1 ^ (~b3 & b5);
            a32 = b2 ^ (~b4 & b6);
            a33 = b3 ^ (~b5 & b7);
            a34 = b4 ^ (~b6 & b8);
            a35 = b5 ^ (~b7 & b9);
            a36 = b6 ^ (~b8 & b0);
            a37 = b7 ^ (~b9 & b1);
            a38 = b8 ^ (~b0 & b2);
            a39 = b9 ^ (~b1 & b3);
            b0 = ((a45 ^ d5) << 30) | ((a44 ^ d4) >>> 2);
            b1 = ((a44 ^ d4) << 30) | ((a45 ^ d5) >>> 2);
            b2 = ((a47 ^ d7) << 23) | ((a46 ^ d6) >>> 9);
            b3 = ((a46 ^ d6) << 23) | ((a47 ^ d7) >>> 9);
            b4 = ((a49 ^ d9) << 7) | ((a48 ^ d8) >>> 25);
            b5 = ((a48 ^ d8) << 7) | ((a49 ^ d9) >>> 25);
            b6 = ((a41 ^ d1) << 9) | ((a40 ^ d0) >>> 23);
            b7 = ((a40 ^ d0) << 9) | ((a41 ^ d1) >>> 23);
            b8 = ((a42 ^ d2) << 2) | ((a43 ^ d3) >>> 30);
            b9 = ((a43 ^ d3) << 2) | ((a42 ^ d2) >>> 30);
            a40 = b0 ^ (~b2 & b4);
            a41 = b1 ^ (~b3 & b5);
            a42 = b2 ^ (~b4 & b6);
            a43 = b3 ^ (~b5 & b7);
            a44 = b4 ^ (~b6 & b8);
            a45 = b5 ^ (~b7 & b9);
            a46 = b6 ^ (~b8 & b0);
            a47 = b7 ^ (~b9 & b1);
            a48 = b8 ^ (~b0 & b2);
            a49 = b9 ^ (~b1 & b3);
        }
        k[0] = (short) a0;
        k[1] = (short) (a0 >>> 16);
        k[2] = (short) a1;
        k[3] = (short) (a1 >>> 16);
        k[4] = (short) a2;
        k[5] = (short) (a2 >>> 16);
        k[6] = (short) a3;
        k[7] = (short) (a3 >>> 16);
        k[8] = (short) a4;
        k[9] = (short) (a4 >>> 16);
        k[10] = (short) a5;
        k[11] = (short) (a5 >>> 16);
        k[12] = (short) a6;
        k[13] = (short) (a6 >>> 16);
        k[14] = (short) a7;
        k[15] = (short) (a7 >>> 16);
        k[16] = (short) a8;
        k[17] = (short) (a8 >>> 16);
        k[18] = (short) a9;
        k[19] = (short) (a9 >>> 16);
        k[20] = (short) a10;
        k[21] = (short) (a10 >>> 16);
        k[22] = (short) a11;
        k[23] = (short) (a11 >>> 16);
        k[24] = (short) a12;
        k[25] = (short) (a12 >>> 16);
        k[26] = (short) a13;
        k[27] = (short) (a13 >>> 16);
        k[28] = (short) a14;
        k[29] = (short) (a14 >>> 16);
        k[30] = (short) a15;
        k[31] = (short) (a15 >>> 16);
        k[32] = (short) a16;
        k[33] = (short) (a16 >>> 16);
        k[34] = (short) a17;
        k[35] = (short) (a17 >>> 16);
        k[36] = (short) a18;
        k[37] = (short) (a18 >>> 16);
        k[38] = (short) a19;
        k[39] = (short) (a19 >>> 16);
        k[40] = (short) a20;
        k[41] = (short) (a20 >>> 16);
        k[42] = (short) a21;
        k[43] = (short) (a21 >>> 16);
        k[44] = (short) a22;
        k[45] = (short) (a22 >>> 16);
        k[46] = (short) a23;
        k[47] = (short) (a23 >>> 16);
        k[48] = (short) a24;
        k[49] = (short) (a24 >>> 16);
        k[50] = (short) a25;
        k[51] = (short) (a25 >>> 16);
        k[52] = (short) a26;
        k[53] = (short) (a26 >>> 16);
        k[54] = (short) a27;
        k[55] = (short) (a27 >>> 16);
        k[56] = (short) a28;
        k[57] = (short) (a28 >>> 16);
        k[58] = (short) a29;
        k[59] = (short) (a29 >>> 16);
        k[60] = (short) a30;
        k[61] = (short) (a30 >>> 16);
        k[62] = (short) a31;
        k[63] = (short) (a31 >>> 16);
        k[64] = (short) a32;
        k[65] = (short) (a32 >>> 16);
        k[66] = (short) a33;
        k[67] = (short) (a33 >>> 16);
        k[68] = (short) a34;
        k[69] = (short) (a34 >>> 16);
        k[70] = (short) a35;
        k[71] = (short) (a35 >>> 16);
        k[72] = (short) a36;
        k[73] = (short) (a36 >>> 16);
        k[74] = (short) a37;
        k[75] = (short) (a37 >>> 16);
        k[76] = (short) a38;
        k[77] = (short) (a38 >>> 16);
        k[78] = (short) a39;
        k[79] = (short) (a39 >>> 16);
        k[80] = (short) a40;
        k[81] = (short) (a40 >>> 16);
        k[82] = (short) a41;
        k[83] = (short) (a41 >>> 16);
        k[84] = (short) a42;
        k[85] = (short) (a42 >>> 16);
        k[86] = (short) a43;
        k[87] = (short) (a43 >>> 16);
        k[88] = (short) a44;
        k[89] = (short) (a44 >>> 16);
        k[90] = (short) a45;
        k[91] = (short) (a45 >>> 16);
        k[92] = (short) a46;
        k[93] = (short) (a46 >>> 16);
        k[94] = (short) a47;
        k[95] = (short) (a47 >>> 16);
        k[96] = (short) a48;
        k[97] = (short) (a48 >>> 16);
        k[98] = (short) a49;
        k[99] = (short) (a49 >>> 16);
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

    /**
     * The same seal as aead() on the generated code. It leaves the tag in
     * mac[48..63] and the first 16 ciphertext bytes in blk[0..15].
     */
    private void aeadFast() {
        short j;
        short[] p = ph;
        // poly key: the first 32 key-stream bytes of block 0
        Util.arrayFillNonAtomic(mac, (short) 0, (short) 416, (byte) 0);
        chachaFast(0, mac, (short) 0, (short) 32);
        for (j = 0; j < 16; j++) {
            p[(short) (17 + j)] = (short) (mac[j] & 0xFF);
            p[(short) (68 + j)] = (short) (mac[(short) (16 + j)] & 0xFF);
        }
        p[20] &= 15; p[21] &= 252; p[24] &= 15; p[25] &= 252; p[28] &= 15; p[29] &= 252; p[32] &= 15;
        // mac layout: aad(40) pad(8) | ct(352) | len aad(8) | len ct(8)
        Util.arrayFillNonAtomic(mac, (short) 0, (short) 48, (byte) 0);
        for (j = 0; j < 40; j++) {
            mac[j] = (byte) (0xA0 + j);
        }
        for (j = 0; j < 352; j++) {
            mac[(short) (48 + j)] = (byte) j;
        }
        mac[400] = 40;
        mac[409] = 0x01;
        mac[408] = 0x60; // 352 = 0x0160
        for (j = 0; j < 320; j += 64) {
            chachaFast((j / 64) + 1, mac, (short) (48 + j), (short) 64);
        }
        chachaFast(6, mac, (short) 368, (short) 32);
        Util.arrayCopyNonAtomic(mac, (short) 48, blk, (short) 0, (short) 16);
        polyFast(mac, (short) 0, (short) 416);
        polyFinish();
    }

    /** XORs one ChaCha20 key-stream block into out[off..off+len); len is 64 or 32. */
    private static void chachaFast(int counter, byte[] out, short off, short len) {
        int x0 = 0x61707865, x1 = 0x3320646e, x2 = 0x79622d32, x3 = 0x6b206574, x4 = 0x03020100, x5 = 0x07060504, x6 = 0x0b0a0908, x7 = 0x0f0e0d0c, x8 = 0x13121110, x9 = 0x17161514, x10 = 0x1b1a1918, x11 = 0x1f1e1d1c, x12 = counter, x13 = 0x03020100, x14 = 0x07060504, x15 = 0x0b0a0908;
        for (short r = 0; r < 10; r++) {
            x0 += x4; x12 ^= x0; x12 = (x12 << 16) | (x12 >>> 16);
            x8 += x12; x4 ^= x8; x4 = (x4 << 12) | (x4 >>> 20);
            x0 += x4; x12 ^= x0; x12 = (x12 << 8) | (x12 >>> 24);
            x8 += x12; x4 ^= x8; x4 = (x4 << 7) | (x4 >>> 25);
            x1 += x5; x13 ^= x1; x13 = (x13 << 16) | (x13 >>> 16);
            x9 += x13; x5 ^= x9; x5 = (x5 << 12) | (x5 >>> 20);
            x1 += x5; x13 ^= x1; x13 = (x13 << 8) | (x13 >>> 24);
            x9 += x13; x5 ^= x9; x5 = (x5 << 7) | (x5 >>> 25);
            x2 += x6; x14 ^= x2; x14 = (x14 << 16) | (x14 >>> 16);
            x10 += x14; x6 ^= x10; x6 = (x6 << 12) | (x6 >>> 20);
            x2 += x6; x14 ^= x2; x14 = (x14 << 8) | (x14 >>> 24);
            x10 += x14; x6 ^= x10; x6 = (x6 << 7) | (x6 >>> 25);
            x3 += x7; x15 ^= x3; x15 = (x15 << 16) | (x15 >>> 16);
            x11 += x15; x7 ^= x11; x7 = (x7 << 12) | (x7 >>> 20);
            x3 += x7; x15 ^= x3; x15 = (x15 << 8) | (x15 >>> 24);
            x11 += x15; x7 ^= x11; x7 = (x7 << 7) | (x7 >>> 25);
            x0 += x5; x15 ^= x0; x15 = (x15 << 16) | (x15 >>> 16);
            x10 += x15; x5 ^= x10; x5 = (x5 << 12) | (x5 >>> 20);
            x0 += x5; x15 ^= x0; x15 = (x15 << 8) | (x15 >>> 24);
            x10 += x15; x5 ^= x10; x5 = (x5 << 7) | (x5 >>> 25);
            x1 += x6; x12 ^= x1; x12 = (x12 << 16) | (x12 >>> 16);
            x11 += x12; x6 ^= x11; x6 = (x6 << 12) | (x6 >>> 20);
            x1 += x6; x12 ^= x1; x12 = (x12 << 8) | (x12 >>> 24);
            x11 += x12; x6 ^= x11; x6 = (x6 << 7) | (x6 >>> 25);
            x2 += x7; x13 ^= x2; x13 = (x13 << 16) | (x13 >>> 16);
            x8 += x13; x7 ^= x8; x7 = (x7 << 12) | (x7 >>> 20);
            x2 += x7; x13 ^= x2; x13 = (x13 << 8) | (x13 >>> 24);
            x8 += x13; x7 ^= x8; x7 = (x7 << 7) | (x7 >>> 25);
            x3 += x4; x14 ^= x3; x14 = (x14 << 16) | (x14 >>> 16);
            x9 += x14; x4 ^= x9; x4 = (x4 << 12) | (x4 >>> 20);
            x3 += x4; x14 ^= x3; x14 = (x14 << 8) | (x14 >>> 24);
            x9 += x14; x4 ^= x9; x4 = (x4 << 7) | (x4 >>> 25);
        }
        x0 += 0x61707865;
        out[off++] ^= (byte) x0;
        out[off++] ^= (byte) (x0 >>> 8);
        out[off++] ^= (byte) (x0 >>> 16);
        out[off++] ^= (byte) (x0 >>> 24);
        x1 += 0x3320646e;
        out[off++] ^= (byte) x1;
        out[off++] ^= (byte) (x1 >>> 8);
        out[off++] ^= (byte) (x1 >>> 16);
        out[off++] ^= (byte) (x1 >>> 24);
        x2 += 0x79622d32;
        out[off++] ^= (byte) x2;
        out[off++] ^= (byte) (x2 >>> 8);
        out[off++] ^= (byte) (x2 >>> 16);
        out[off++] ^= (byte) (x2 >>> 24);
        x3 += 0x6b206574;
        out[off++] ^= (byte) x3;
        out[off++] ^= (byte) (x3 >>> 8);
        out[off++] ^= (byte) (x3 >>> 16);
        out[off++] ^= (byte) (x3 >>> 24);
        x4 += 0x03020100;
        out[off++] ^= (byte) x4;
        out[off++] ^= (byte) (x4 >>> 8);
        out[off++] ^= (byte) (x4 >>> 16);
        out[off++] ^= (byte) (x4 >>> 24);
        x5 += 0x07060504;
        out[off++] ^= (byte) x5;
        out[off++] ^= (byte) (x5 >>> 8);
        out[off++] ^= (byte) (x5 >>> 16);
        out[off++] ^= (byte) (x5 >>> 24);
        x6 += 0x0b0a0908;
        out[off++] ^= (byte) x6;
        out[off++] ^= (byte) (x6 >>> 8);
        out[off++] ^= (byte) (x6 >>> 16);
        out[off++] ^= (byte) (x6 >>> 24);
        x7 += 0x0f0e0d0c;
        out[off++] ^= (byte) x7;
        out[off++] ^= (byte) (x7 >>> 8);
        out[off++] ^= (byte) (x7 >>> 16);
        out[off++] ^= (byte) (x7 >>> 24);
        if (len == 32) {
            return;
        }
        x8 += 0x13121110;
        out[off++] ^= (byte) x8;
        out[off++] ^= (byte) (x8 >>> 8);
        out[off++] ^= (byte) (x8 >>> 16);
        out[off++] ^= (byte) (x8 >>> 24);
        x9 += 0x17161514;
        out[off++] ^= (byte) x9;
        out[off++] ^= (byte) (x9 >>> 8);
        out[off++] ^= (byte) (x9 >>> 16);
        out[off++] ^= (byte) (x9 >>> 24);
        x10 += 0x1b1a1918;
        out[off++] ^= (byte) x10;
        out[off++] ^= (byte) (x10 >>> 8);
        out[off++] ^= (byte) (x10 >>> 16);
        out[off++] ^= (byte) (x10 >>> 24);
        x11 += 0x1f1e1d1c;
        out[off++] ^= (byte) x11;
        out[off++] ^= (byte) (x11 >>> 8);
        out[off++] ^= (byte) (x11 >>> 16);
        out[off++] ^= (byte) (x11 >>> 24);
        x12 += counter;
        out[off++] ^= (byte) x12;
        out[off++] ^= (byte) (x12 >>> 8);
        out[off++] ^= (byte) (x12 >>> 16);
        out[off++] ^= (byte) (x12 >>> 24);
        x13 += 0x03020100;
        out[off++] ^= (byte) x13;
        out[off++] ^= (byte) (x13 >>> 8);
        out[off++] ^= (byte) (x13 >>> 16);
        out[off++] ^= (byte) (x13 >>> 24);
        x14 += 0x07060504;
        out[off++] ^= (byte) x14;
        out[off++] ^= (byte) (x14 >>> 8);
        out[off++] ^= (byte) (x14 >>> 16);
        out[off++] ^= (byte) (x14 >>> 24);
        x15 += 0x0b0a0908;
        out[off++] ^= (byte) x15;
        out[off++] ^= (byte) (x15 >>> 8);
        out[off++] ^= (byte) (x15 >>> 16);
        out[off++] ^= (byte) (x15 >>> 24);
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

    /** Poly1305 over len bytes of m (whole 16-byte blocks) with r in ph[17..32]; leaves h in ph[0..16]. */
    private void polyFast(byte[] m, short off, short len) {
        short[] p = ph;
        int t0 = p[17] | (p[18] << 8), t1 = p[19] | (p[20] << 8), t2 = p[21] | (p[22] << 8), t3 = p[23] | (p[24] << 8), t4 = p[25] | (p[26] << 8), t5 = p[27] | (p[28] << 8), t6 = p[29] | (p[30] << 8), t7 = p[31] | (p[32] << 8);
        int r0 = t0 & 0x1FFF, r1 = ((t0 >>> 13) | (t1 << 3)) & 0x1FFF, r2 = ((t1 >>> 10) | (t2 << 6)) & 0x1FFF, r3 = ((t2 >>> 7) | (t3 << 9)) & 0x1FFF, r4 = ((t3 >>> 4) | (t4 << 12)) & 0x1FFF, r5 = (t4 >>> 1) & 0x1FFF, r6 = ((t4 >>> 14) | (t5 << 2)) & 0x1FFF, r7 = ((t5 >>> 11) | (t6 << 5)) & 0x1FFF, r8 = ((t6 >>> 8) | (t7 << 8)) & 0x1FFF, r9 = (t7 >>> 5) & 0x1FFF;
        int s1 = 5 * r1, s2 = 5 * r2, s3 = 5 * r3, s4 = 5 * r4, s5 = 5 * r5, s6 = 5 * r6, s7 = 5 * r7, s8 = 5 * r8, s9 = 5 * r9;
        int h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0, h5 = 0, h6 = 0, h7 = 0, h8 = 0, h9 = 0;
        int x0, x1, x2, x3, x4, x5, x6, x7, x8, x9;
        int u;
        short end = (short) (off + len);
        for (short o = off; o < end; o += 16) {
            t0 = (m[(short) (o + 0)] & 0xFF) | ((m[(short) (o + 1)] & 0xFF) << 8);
            t1 = (m[(short) (o + 2)] & 0xFF) | ((m[(short) (o + 3)] & 0xFF) << 8);
            t2 = (m[(short) (o + 4)] & 0xFF) | ((m[(short) (o + 5)] & 0xFF) << 8);
            t3 = (m[(short) (o + 6)] & 0xFF) | ((m[(short) (o + 7)] & 0xFF) << 8);
            t4 = (m[(short) (o + 8)] & 0xFF) | ((m[(short) (o + 9)] & 0xFF) << 8);
            t5 = (m[(short) (o + 10)] & 0xFF) | ((m[(short) (o + 11)] & 0xFF) << 8);
            t6 = (m[(short) (o + 12)] & 0xFF) | ((m[(short) (o + 13)] & 0xFF) << 8);
            t7 = (m[(short) (o + 14)] & 0xFF) | ((m[(short) (o + 15)] & 0xFF) << 8);
            h0 += (t0 & 0x1FFF);
            h1 += (((t0 >>> 13) | (t1 << 3)) & 0x1FFF);
            h2 += (((t1 >>> 10) | (t2 << 6)) & 0x1FFF);
            h3 += (((t2 >>> 7) | (t3 << 9)) & 0x1FFF);
            h4 += (((t3 >>> 4) | (t4 << 12)) & 0x1FFF);
            h5 += ((t4 >>> 1) & 0x1FFF);
            h6 += (((t4 >>> 14) | (t5 << 2)) & 0x1FFF);
            h7 += (((t5 >>> 11) | (t6 << 5)) & 0x1FFF);
            h8 += (((t6 >>> 8) | (t7 << 8)) & 0x1FFF);
            h9 += ((t7 >>> 5) & 0x1FFF) + 0x800;
            u = 0;
            x0 = u + h0 * r0 + h1 * s9 + h2 * s8 + h3 * s7 + h4 * s6;
            u = x0 >>> 13;
            x0 = (x0 & 0x1FFF) + h5 * s5 + h6 * s4 + h7 * s3 + h8 * s2 + h9 * s1;
            u += x0 >>> 13;
            x1 = u + h0 * r1 + h1 * r0 + h2 * s9 + h3 * s8 + h4 * s7;
            u = x1 >>> 13;
            x1 = (x1 & 0x1FFF) + h5 * s6 + h6 * s5 + h7 * s4 + h8 * s3 + h9 * s2;
            u += x1 >>> 13;
            x2 = u + h0 * r2 + h1 * r1 + h2 * r0 + h3 * s9 + h4 * s8;
            u = x2 >>> 13;
            x2 = (x2 & 0x1FFF) + h5 * s7 + h6 * s6 + h7 * s5 + h8 * s4 + h9 * s3;
            u += x2 >>> 13;
            x3 = u + h0 * r3 + h1 * r2 + h2 * r1 + h3 * r0 + h4 * s9;
            u = x3 >>> 13;
            x3 = (x3 & 0x1FFF) + h5 * s8 + h6 * s7 + h7 * s6 + h8 * s5 + h9 * s4;
            u += x3 >>> 13;
            x4 = u + h0 * r4 + h1 * r3 + h2 * r2 + h3 * r1 + h4 * r0;
            u = x4 >>> 13;
            x4 = (x4 & 0x1FFF) + h5 * s9 + h6 * s8 + h7 * s7 + h8 * s6 + h9 * s5;
            u += x4 >>> 13;
            x5 = u + h0 * r5 + h1 * r4 + h2 * r3 + h3 * r2 + h4 * r1;
            u = x5 >>> 13;
            x5 = (x5 & 0x1FFF) + h5 * r0 + h6 * s9 + h7 * s8 + h8 * s7 + h9 * s6;
            u += x5 >>> 13;
            x6 = u + h0 * r6 + h1 * r5 + h2 * r4 + h3 * r3 + h4 * r2;
            u = x6 >>> 13;
            x6 = (x6 & 0x1FFF) + h5 * r1 + h6 * r0 + h7 * s9 + h8 * s8 + h9 * s7;
            u += x6 >>> 13;
            x7 = u + h0 * r7 + h1 * r6 + h2 * r5 + h3 * r4 + h4 * r3;
            u = x7 >>> 13;
            x7 = (x7 & 0x1FFF) + h5 * r2 + h6 * r1 + h7 * r0 + h8 * s9 + h9 * s8;
            u += x7 >>> 13;
            x8 = u + h0 * r8 + h1 * r7 + h2 * r6 + h3 * r5 + h4 * r4;
            u = x8 >>> 13;
            x8 = (x8 & 0x1FFF) + h5 * r3 + h6 * r2 + h7 * r1 + h8 * r0 + h9 * s9;
            u += x8 >>> 13;
            x9 = u + h0 * r9 + h1 * r8 + h2 * r7 + h3 * r6 + h4 * r5;
            u = x9 >>> 13;
            x9 = (x9 & 0x1FFF) + h5 * r4 + h6 * r3 + h7 * r2 + h8 * r1 + h9 * r0;
            u += x9 >>> 13;
            u = 5 * u + (x0 & 0x1FFF);
            h0 = u & 0x1FFF;
            h1 = (x1 & 0x1FFF) + (u >>> 13);
            h2 = x2 & 0x1FFF;
            h3 = x3 & 0x1FFF;
            h4 = x4 & 0x1FFF;
            h5 = x5 & 0x1FFF;
            h6 = x6 & 0x1FFF;
            h7 = x7 & 0x1FFF;
            h8 = x8 & 0x1FFF;
            h9 = x9 & 0x1FFF;
        }
        u = h1 >>> 13; h1 &= 0x1FFF;
        u += h2; h2 = u & 0x1FFF; u >>>= 13;
        u += h3; h3 = u & 0x1FFF; u >>>= 13;
        u += h4; h4 = u & 0x1FFF; u >>>= 13;
        u += h5; h5 = u & 0x1FFF; u >>>= 13;
        u += h6; h6 = u & 0x1FFF; u >>>= 13;
        u += h7; h7 = u & 0x1FFF; u >>>= 13;
        u += h8; h8 = u & 0x1FFF; u >>>= 13;
        u += h9; h9 = u & 0x1FFF; u >>>= 13;
        u = 5 * u + h0; h0 = u & 0x1FFF; h1 += u >>> 13;
        u = 0;
        u += h0;
        p[0] = (short) (u & 255); u >>>= 8;
        u += h1 << 5;
        p[1] = (short) (u & 255); u >>>= 8;
        p[2] = (short) (u & 255); u >>>= 8;
        u += h2 << 2;
        p[3] = (short) (u & 255); u >>>= 8;
        u += h3 << 7;
        p[4] = (short) (u & 255); u >>>= 8;
        p[5] = (short) (u & 255); u >>>= 8;
        u += h4 << 4;
        p[6] = (short) (u & 255); u >>>= 8;
        p[7] = (short) (u & 255); u >>>= 8;
        u += h5 << 1;
        p[8] = (short) (u & 255); u >>>= 8;
        u += h6 << 6;
        p[9] = (short) (u & 255); u >>>= 8;
        p[10] = (short) (u & 255); u >>>= 8;
        u += h7 << 3;
        p[11] = (short) (u & 255); u >>>= 8;
        p[12] = (short) (u & 255); u >>>= 8;
        u += h8;
        p[13] = (short) (u & 255); u >>>= 8;
        u += h9 << 5;
        p[14] = (short) (u & 255); u >>>= 8;
        p[15] = (short) (u & 255); u >>>= 8;
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
