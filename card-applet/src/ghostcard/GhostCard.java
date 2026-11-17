package ghostcard;

import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.RandomData;
import javacardx.apdu.ExtendedLength;

/**
 * The Ghost bearer card applet, as docs/bearer-card-spec.md describes it.
 *
 * The card draws each fill's Phantom Key itself, computes the coin's F,
 * commitment, marker and sealed note exactly as Ghost's client does, signs
 * seal statements with an LMS key made on the card, and releases a fill's
 * seed material to whoever holds the card and opens it: the card is a bearer
 * object, and no code or PIN stands between the holder and the GHOST. Until
 * Open, no command returns the key or the card random; none ever returns the
 * LMS private seed or the applet's code.
 *
 * Commands (CLA 0x80) are listed in card-applet/README.md.
 */
public final class GhostCard extends Applet implements ExtendedLength {

    // ---------------- commands ----------------

    private static final byte CLA = (byte) 0x80;
    private static final byte INS_IDENTIFY = (byte) 0x10;
    private static final byte INS_READ_CERT = (byte) 0x12;
    private static final byte INS_PUBLIC_KEY = (byte) 0x14;
    private static final byte INS_MAKE = (byte) 0x20;
    private static final byte INS_COMMIT_DATA = (byte) 0x22;
    private static final byte INS_CHECK = (byte) 0x30;
    private static final byte INS_READ_SIGNATURE = (byte) 0x32;
    private static final byte INS_OPEN = (byte) 0x40;
    private static final byte INS_REFILL = (byte) 0x50;
    private static final byte INS_GENERATE = (byte) 0x60;
    private static final byte INS_WRITE_CERT = (byte) 0x64;
    private static final byte INS_FINISH = (byte) 0x66;

    /** The command is not allowed in the card's current state. */
    static final short SW_WRONG_STATE = (short) 0x6985;
    /** Too few seal checks left (Make) or none at all (Check). */
    static final short SW_NO_CHECKS = (short) 0x6984;

    // ---------------- phases and states ----------------

    static final byte PHASE_LOADING = 0;
    static final byte PHASE_READY = 1;
    static final byte STATE_BLANK = 0;
    static final byte STATE_SEALED = 1;
    static final byte STATE_OPENED = 2;

    /** Identify's answer format. */
    private static final byte FORMAT = 1;

    // ---------------- sizes ----------------

    private static final short HEIGHT = 10;
    private static final short LEAVES = 1024;
    /** Make refuses on a card with fewer seal checks left than this. */
    private static final short MIN_CHECKS_TO_MAKE = 16;
    /** Tree nodes 2..2047 in two arrays of 1023 nodes (the root is in the public key). */
    private static final short NODES_PER_ARRAY = 1023;
    private static final short CERT_DEFAULT = 8192;
    /** The most certificate bytes one WRITE CERT takes. */
    private static final short CERT_PART = 512;

    private static final short ID_LEN = 16;
    private static final short CD_LEN = 430;
    private static final short NOTE_BODY = 352;
    private static final short MAKE_IN = 52;
    private static final short MAKE_OUT = 466;
    private static final short OPEN_OUT = 68;
    private static final short STATEMENT_LEN = 193;
    private static final short SIG_LEN = 2508;
    private static final short PUB_LEN = 56;
    private static final short IDENTIFY_LEN = 29;

    // RFC 8554 type codes and domain separators.
    private static final byte LMS_SHA256_M32_H10 = 6;
    private static final byte LMOTS_SHA256_N32_W4 = 3;
    private static final short OTS_CHAINS = 67;
    private static final byte D_PBLC = (byte) 0x80;
    private static final byte D_MESG = (byte) 0x81;
    private static final byte D_LEAF = (byte) 0x82;
    private static final byte D_INTR = (byte) 0x83;

    // ---------------- persistent layout ----------------

    // meta
    private static final short M_PHASE = 0;
    private static final short M_STATE = 1;
    private static final short M_FILL = 2;      // 4 bytes, big-endian
    private static final short M_NEXT_LEAF = 6; // the next LMS leaf to sign with
    private static final short M_KEYGEN = 8;    // LMS leaves generated so far
    private static final short M_CERT_LEN = 10;
    private static final short META_LEN = 12;

    // the fill: meaningful only while the state is sealed or opened
    private static final short F_RAND = 0;
    private static final short F_NONCE = 32;
    private static final short F_AMOUNT = 64;
    private static final short F_CHAIN = 76;
    private static final short F_C = 84;
    private static final short F_DIGEST = 116;
    private static final short F_MARKER = 148;
    private static final short F_CD = 180;
    private static final short FILL_LEN = 610;

    // ---------------- RAM work layout ----------------

    // Make
    private static final short W_CD = 0;       // commit data, 430
    private static final short W_KEY = 430;    // 0x20 || seed bytes, 33
    private static final short W_S = 463;
    private static final short W_R = 495;
    private static final short W_B = 527;
    private static final short W_NK = 559;     // note key, then the note nonce: the ChaCha20 key and nonce
    private static final short W_NONCE = 591;  // 12
    private static final short W_F = 603;
    private static final short W_C = 635;
    private static final short W_M = 667;
    private static final short W_RAND = 699;
    private static final short W_WN = 731;     // writer nonce
    private static final short W_AMT = 763;    // 12
    private static final short W_CHAIN = 775;  // 8
    private static final short W_SALT = 783;   // 16
    private static final short W_DIG = 799;
    private static final short W_TMP = 831;    // 64
    private static final short WORK_LEN = 895;

    // Check: the statement
    private static final short S_ID = 18;
    private static final short S_STATE = 34;
    private static final short S_FILL = 35;
    private static final short S_CHAIN = 39;
    private static final short S_AMT = 47;
    private static final short S_C = 59;
    private static final short S_DIG = 91;
    private static final short S_M = 123;
    private static final short S_LEFT = 155;
    private static final short S_LEAF = 157;
    private static final short S_CHAL = 161;
    private static final short C_TMP = 200;    // 32

    // The signing context of the last Check: valid 1 || q 4 || C 32 || Q 32 || checksum 2.
    private static final short X_VALID = 0;
    private static final short X_Q = 1;
    private static final short X_C = 5;
    private static final short X_QD = 37;
    private static final short CTX_LEN = 71;

    // lb: I 16 || q 4 || i 2 || j 1 || tmp 32, the LM-OTS chain input
    private static final short LB_Q = 16;
    private static final short LB_I = 20;
    private static final short LB_J = 22;
    private static final short LB_TMP = 23;
    private static final short LB_LEN = 55;

    // Sponge padding
    private static final byte PAD_SHA3 = 0x06;
    private static final byte PAD_KECCAK = 0x01;
    private static final short RATE = 136;

    // ---------------- domains ----------------

    private static final byte[] T_SECRET = {15, 'g', 'h', 'o', 's', 't', '/', 's', 'e', 'c', 'r', 'e', 't', '/', 'v', '1'};
    private static final byte[] T_REVEAL = {22, 'g', 'h', 'o', 's', 't', '/', 'r', 'e', 'v', 'e', 'a', 'l', '-', 's', 'e', 'c', 'r', 'e', 't', '/', 'v', '1'};
    private static final byte[] T_BLINDING = {17, 'g', 'h', 'o', 's', 't', '/', 'b', 'l', 'i', 'n', 'd', 'i', 'n', 'g', '/', 'v', '1'};
    private static final byte[] T_NOTE_KEY = {17, 'g', 'h', 'o', 's', 't', '/', 'n', 'o', 't', 'e', '-', 'k', 'e', 'y', '/', 'v', '1'};
    private static final byte[] T_NOTE_TAG = {17, 'g', 'h', 'o', 's', 't', '/', 'n', 'o', 't', 'e', '-', 't', 'a', 'g', '/', 'v', '1'};
    private static final byte[] T_FINGERPRINT = {25, 'g', 'h', 'o', 's', 't', '/', 'c', 'o', 'i', 'n', '-', 'f', 'i', 'n', 'g', 'e', 'r', 'p', 'r', 'i', 'n', 't', '/', 'v', '2'};
    private static final byte[] T_COMMITMENT = {24, 'g', 'h', 'o', 's', 't', '/', 'c', 'o', 'i', 'n', '-', 'c', 'o', 'm', 'm', 'i', 't', 'm', 'e', 'n', 't', '/', 'v', '1'};
    private static final byte[] T_MARKER = {20, 'g', 'h', 'o', 's', 't', '/', 'c', 'o', 'i', 'n', '-', 'm', 'a', 'r', 'k', 'e', 'r', '/', 'v', '2'};
    private static final byte[] D_KEY = {'g', 'h', 'o', 's', 't', '-', 'c', 'a', 'r', 'd', '-', 'k', 'e', 'y'};
    private static final byte[] D_SEAL = {'g', 'h', 'o', 's', 't', '-', 'c', 'a', 'r', 'd', '-', 's', 'e', 'a', 'l', '-', 'v', '2'};

    // ---------------- fields (set once, at install) ----------------

    private final byte[] meta;
    private final byte[] cardId;
    private final byte[] lmsSeed;
    private final byte[] pub;
    private final byte[] tree0;
    private final byte[] tree1;
    private final byte[] fill;
    private final byte[] cert;

    private final byte[] w;
    private final byte[] ctx;
    private final byte[] lb;
    private final byte[] lh;
    private final short[] ks;
    private final short[] ph;
    private final short[] sv;

    private final MessageDigest sha;
    private final MessageDigest shaK;
    private RandomData rng;

    private GhostCard(byte[] params, short off, byte len) {
        short certCap = CERT_DEFAULT;
        if (len >= 2) {
            certCap = Util.getShort(params, off);
            if (certCap <= 0) {
                ISOException.throwIt(ISO7816.SW_WRONG_DATA);
            }
        }
        meta = new byte[META_LEN];
        cardId = new byte[ID_LEN];
        lmsSeed = new byte[32];
        pub = new byte[PUB_LEN];
        tree0 = new byte[(short) (NODES_PER_ARRAY * 32)];
        tree1 = new byte[(short) (NODES_PER_ARRAY * 32)];
        fill = new byte[FILL_LEN];
        cert = new byte[certCap];

        w = JCSystem.makeTransientByteArray(WORK_LEN, JCSystem.CLEAR_ON_DESELECT);
        ctx = JCSystem.makeTransientByteArray(CTX_LEN, JCSystem.CLEAR_ON_DESELECT);
        lb = JCSystem.makeTransientByteArray(LB_LEN, JCSystem.CLEAR_ON_DESELECT);
        lh = JCSystem.makeTransientByteArray((short) 64, JCSystem.CLEAR_ON_DESELECT);
        ks = JCSystem.makeTransientShortArray((short) 100, JCSystem.CLEAR_ON_DESELECT);
        ph = JCSystem.makeTransientShortArray((short) 102, JCSystem.CLEAR_ON_DESELECT);
        sv = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);

        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        shaK = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);
        rng = RandomData.getInstance(RandomData.ALG_TRNG);

        // The card id (also the LMS identifier I) and the LMS private seed
        // come from the card's own random source.
        rng.nextBytes(w, (short) 0, (short) 48);
        Nvm.copy(w, (short) 0, cardId, (short) 0, ID_LEN);
        Nvm.copy(w, ID_LEN, lmsSeed, (short) 0, (short) 32);
        Util.arrayFillNonAtomic(w, (short) 0, (short) 48, (byte) 0);
        // The public key: u32 LMS type || u32 LM-OTS type || I || T[1].
        w[3] = LMS_SHA256_M32_H10;
        w[7] = LMOTS_SHA256_N32_W4;
        Util.arrayCopyNonAtomic(cardId, (short) 0, w, (short) 8, ID_LEN);
        Nvm.copy(w, (short) 0, pub, (short) 0, (short) 24);
        Util.arrayFillNonAtomic(w, (short) 0, (short) 24, (byte) 0);
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        // Skip the instance AID and the privileges to reach the applet's own parameters.
        short o = bOffset;
        o += (short) (1 + bArray[o]);
        o += (short) (1 + bArray[o]);
        byte len = bArray[o];
        new GhostCard(bArray, (short) (o + 1), len).register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buf = apdu.getBuffer();
        if (buf[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }
        byte ins = buf[ISO7816.OFFSET_INS];
        // A signing context lives only until the next command other than
        // READ SIGNATURE, so no LMS leaf is ever used with two messages.
        if (ins != INS_READ_SIGNATURE) {
            ctx[X_VALID] = 0;
        }
        switch (ins) {
            case INS_IDENTIFY:
                identify(apdu);
                return;
            case INS_READ_CERT:
                readCert(apdu);
                return;
            case INS_PUBLIC_KEY:
                publicKey(apdu);
                return;
            case INS_MAKE:
                make(apdu);
                return;
            case INS_COMMIT_DATA:
                commitData(apdu);
                return;
            case INS_CHECK:
                check(apdu);
                return;
            case INS_READ_SIGNATURE:
                readSignature(apdu);
                return;
            case INS_OPEN:
                open(apdu);
                return;
            case INS_REFILL:
                refill(apdu);
                return;
            case INS_GENERATE:
                generate(apdu);
                return;
            case INS_WRITE_CERT:
                writeCert(apdu);
                return;
            case INS_FINISH:
                finish(apdu);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // ---------------- small helpers ----------------

    private byte phase() {
        return meta[M_PHASE];
    }

    private byte state() {
        return meta[M_STATE];
    }

    private short checksLeft() {
        return (short) (LEAVES - Util.getShort(meta, M_NEXT_LEAF));
    }

    private static void require(boolean ok, short sw) {
        if (!ok) {
            ISOException.throwIt(sw);
        }
    }

    /** Receives exactly `len` command data bytes into the APDU buffer and returns their offset. */
    private static short receive(APDU apdu, short len) {
        short got = apdu.setIncomingAndReceive();
        require(apdu.getIncomingLength() == len && got == len, ISO7816.SW_WRONG_LENGTH);
        return apdu.getOffsetCdata();
    }

    /** Sends data[off..off+len), cut to the length the reader asked for. */
    private static void send(APDU apdu, byte[] data, short off, short len) {
        short le = apdu.setOutgoing();
        if (le < len) {
            len = le;
        }
        apdu.setOutgoingLength(len);
        apdu.sendBytesLong(data, off, len);
    }

    /** Sends part of a stored byte string: the offset is P1P2, the length the reader's Le. */
    private static void sendPart(APDU apdu, byte[] data, short dataOff, short total) {
        byte[] buf = apdu.getBuffer();
        short at = Util.getShort(buf, ISO7816.OFFSET_P1);
        require(at >= 0 && at <= total, ISO7816.SW_INCORRECT_P1P2);
        send(apdu, data, (short) (dataOff + at), (short) (total - at));
    }

    /** Compares without stopping at the first difference. */
    private static boolean same(byte[] a, short ao, byte[] b, short bo, short len) {
        byte d = 0;
        for (short i = 0; i < len; i++) {
            d |= (byte) (a[(short) (ao + i)] ^ b[(short) (bo + i)]);
        }
        return d == 0;
    }

    // ---------------- the Keccak sponge (rate 136: SHA3-256 and Keccak-256) ----------------

    private void spBegin() {
        short[] k = ks;
        for (short i = 0; i < 100; i++) {
            k[i] = 0;
        }
        sv[0] = 0;
    }

    private void spAbsorb(byte[] b, short off, short len) {
        short[] k = ks;
        short p = sv[0];
        short end = (short) (off + len);
        for (short i = off; i < end; i++) {
            short v = (short) (b[i] & 0xFF);
            if ((p & 1) == 0) {
                k[(short) (p >> 1)] ^= v;
            } else {
                k[(short) (p >> 1)] ^= (short) (v << 8);
            }
            p++;
            if (p == RATE) {
                KeccakF.permute(k);
                p = 0;
            }
        }
        sv[0] = p;
    }

    private void spZeros(short len) {
        short p = sv[0];
        while (len > 0) {
            short room = (short) (RATE - p);
            short n = len < room ? len : room;
            p += n;
            len -= n;
            if (p == RATE) {
                KeccakF.permute(ks);
                p = 0;
            }
        }
        sv[0] = p;
    }

    /** Pads, permutes and writes the 32-byte digest to out[off..]. */
    private void spFinish(byte pad, byte[] out, short off) {
        short[] k = ks;
        short p = sv[0];
        if ((p & 1) == 0) {
            k[(short) (p >> 1)] ^= (short) (pad & 0xFF);
        } else {
            k[(short) (p >> 1)] ^= (short) ((pad & 0xFF) << 8);
        }
        k[67] ^= (short) 0x8000; // the last rate byte, 135
        KeccakF.permute(k);
        for (short j = 0; j < 16; j++) {
            out[(short) (off + 2 * j)] = (byte) k[j];
            out[(short) (off + 2 * j + 1)] = (byte) (k[j] >> 8);
        }
        for (short i = 0; i < 100; i++) {
            k[i] = 0;
        }
    }

    /** Ghost's tagged hash of the 33 key bytes: SHA3-256(len(tag) || tag || key bytes). */
    private void keyHash(byte[] tag, short out) {
        spBegin();
        spAbsorb(tag, (short) 0, (short) tag.length);
        spAbsorb(w, W_KEY, (short) 33);
        spFinish(PAD_SHA3, w, out);
    }

    // ---------------- Identify, certificate, public key ----------------

    private void identify(APDU apdu) {
        byte[] o = lh;
        o[0] = FORMAT;
        o[1] = phase();
        o[2] = state();
        Util.arrayCopyNonAtomic(cardId, (short) 0, o, (short) 3, ID_LEN);
        Util.arrayCopyNonAtomic(meta, M_FILL, o, (short) 19, (short) 4);
        Util.setShort(o, (short) 23, checksLeft());
        Util.setShort(o, (short) 25, Util.getShort(meta, M_KEYGEN));
        Util.setShort(o, (short) 27, Util.getShort(meta, M_CERT_LEN));
        send(apdu, o, (short) 0, IDENTIFY_LEN);
    }

    private void readCert(APDU apdu) {
        require(phase() == PHASE_READY, SW_WRONG_STATE);
        sendPart(apdu, cert, (short) 0, Util.getShort(meta, M_CERT_LEN));
    }

    private void publicKey(APDU apdu) {
        require(Util.getShort(meta, M_KEYGEN) == LEAVES, SW_WRONG_STATE);
        send(apdu, pub, (short) 0, PUB_LEN);
    }

    // ---------------- Make ----------------

    /**
     * Make: amount 12 || chain id 8 || writer nonce 32.
     * Answers fill 4 || commitment 32 || commit data 430, unsigned.
     */
    private void make(APDU apdu) {
        require(phase() == PHASE_READY && state() == STATE_BLANK, SW_WRONG_STATE);
        require(checksLeft() >= MIN_CHECKS_TO_MAKE, SW_NO_CHECKS);
        byte[] buf = apdu.getBuffer();
        short in = receive(apdu, MAKE_IN);
        byte[] b = w;
        Util.arrayFillNonAtomic(b, (short) 0, WORK_LEN, (byte) 0);
        Util.arrayCopyNonAtomic(buf, in, b, W_AMT, (short) 12);
        Util.arrayCopyNonAtomic(buf, (short) (in + 12), b, W_CHAIN, (short) 8);
        Util.arrayCopyNonAtomic(buf, (short) (in + 20), b, W_WN, (short) 32);

        rng.nextBytes(b, W_RAND, (short) 32);
        rng.nextBytes(b, W_SALT, (short) 16);
        rng.nextBytes(b, (short) (W_NONCE + 3), (short) 9);

        // The Phantom Key: seed bytes = SHA3-256("ghost-card-key" || card random || writer nonce).
        spBegin();
        spAbsorb(D_KEY, (short) 0, (short) D_KEY.length);
        spAbsorb(b, W_RAND, (short) 64); // card random, then the writer nonce right after it
        spFinish(PAD_SHA3, b, (short) (W_KEY + 1));
        b[W_KEY] = 0x20; // the key format code of a words key

        // Its secrets (Ghost spec 01, section 7): s, r, b0 and the note key.
        keyHash(T_SECRET, W_S);
        keyHash(T_REVEAL, W_R);
        keyHash(T_NOTE_KEY, W_NK);
        spBegin();
        spAbsorb(T_BLINDING, (short) 0, (short) T_BLINDING.length);
        spAbsorb(b, W_KEY, (short) 33);
        spZeros((short) 8); // index 0
        spFinish(PAD_SHA3, b, W_B);

        // The note's lookup tag: the first 3 bytes of SHA3-256 over the note key and number 0.
        spBegin();
        spAbsorb(T_NOTE_TAG, (short) 0, (short) T_NOTE_TAG.length);
        spAbsorb(b, W_NK, (short) 32);
        spZeros((short) 8);
        spFinish(PAD_SHA3, b, W_TMP);
        Util.arrayCopyNonAtomic(b, W_TMP, b, W_NONCE, (short) 3);

        // F = K(coin-fingerprint/v2, s, r, b0, salt, COIN_V2, empty content, empty rule).
        spBegin();
        spAbsorb(T_FINGERPRINT, (short) 0, (short) T_FINGERPRINT.length);
        spAbsorb(b, W_S, (short) 96); // s, r, b0 lie next to each other
        spAbsorb(b, W_SALT, (short) 16);
        b[W_TMP] = 0x02;
        b[(short) (W_TMP + 1)] = 0x01;
        spAbsorb(b, W_TMP, (short) 2);
        spZeros((short) 64);
        spFinish(PAD_KECCAK, b, W_F);

        // C = K(coin-commitment/v1, COIN_V2, F, amount as 32 bytes).
        spBegin();
        spAbsorb(T_COMMITMENT, (short) 0, (short) T_COMMITMENT.length);
        b[W_TMP] = 0x02;
        b[(short) (W_TMP + 1)] = 0x01;
        spAbsorb(b, W_TMP, (short) 2);
        spAbsorb(b, W_F, (short) 32);
        spZeros((short) 20);
        spAbsorb(b, W_AMT, (short) 12);
        spFinish(PAD_KECCAK, b, W_C);

        // marker = K(coin-marker/v2, r, b0, salt).
        spBegin();
        spAbsorb(T_MARKER, (short) 0, (short) T_MARKER.length);
        spAbsorb(b, W_R, (short) 64);
        spAbsorb(b, W_SALT, (short) 16);
        spFinish(PAD_KECCAK, b, W_M);

        sealNote();

        // The commit data's header: version 3 || F || salt || nonce.
        b[W_CD] = 0x00;
        b[(short) (W_CD + 1)] = 0x03;
        Util.arrayCopyNonAtomic(b, W_F, b, (short) (W_CD + 2), (short) 32);
        Util.arrayCopyNonAtomic(b, W_SALT, b, (short) (W_CD + 34), (short) 16);
        Util.arrayCopyNonAtomic(b, W_NONCE, b, (short) (W_CD + 50), (short) 12);
        sha.reset();
        sha.doFinal(b, W_CD, CD_LEN, b, W_DIG);

        // The derived secrets are no longer needed.
        Util.arrayFillNonAtomic(b, W_KEY, (short) (W_F - W_KEY), (byte) 0);

        // One atomic write: the fill's data, the next fill number and the sealed state.
        int n = getInt(meta, M_FILL) + 1;
        setInt(b, W_TMP, n);
        byte[] f = fill;
        Nvm.begin();
        Nvm.copy(b, W_RAND, f, F_RAND, (short) 64); // card random, then the writer nonce
        Nvm.copy(b, W_AMT, f, F_AMOUNT, (short) 20); // amount, then chain id
        Nvm.copy(b, W_C, f, F_C, (short) 32);
        Nvm.copy(b, W_DIG, f, F_DIGEST, (short) 32);
        Nvm.copy(b, W_M, f, F_MARKER, (short) 32);
        Nvm.copy(b, W_CD, f, F_CD, CD_LEN);
        Nvm.copy(b, W_TMP, meta, M_FILL, (short) 4);
        Nvm.setByte(meta, M_STATE, STATE_SEALED);
        Nvm.commit();
        Util.arrayFillNonAtomic(b, W_RAND, (short) 64, (byte) 0);

        // Answer: fill || C, laid out right after the commit data, then the commit data.
        Util.arrayCopyNonAtomic(b, W_TMP, b, W_KEY, (short) 4);
        Util.arrayCopyNonAtomic(b, W_C, b, (short) (W_KEY + 4), (short) 32);
        short le = apdu.setOutgoing();
        short total = le < MAKE_OUT ? le : MAKE_OUT;
        apdu.setOutgoingLength(total);
        short head = total < 36 ? total : 36;
        apdu.sendBytesLong(b, W_KEY, head);
        if (total > 36) {
            apdu.sendBytesLong(b, W_CD, (short) (total - 36));
        }
        Util.arrayFillNonAtomic(b, (short) 0, WORK_LEN, (byte) 0);
    }

    /** Seals the version 3 note into the commit data with ChaCha20-Poly1305, as Ghost's client does. */
    private void sealNote() {
        byte[] b = w;
        short[] p = ph;
        short body = (short) (W_CD + 62);
        // The plaintext: version 3, scheme 1, COIN_V2, number 0, amount, empty
        // content and rule, salt, zero padding, empty capsule.
        Util.arrayFillNonAtomic(b, W_CD, CD_LEN, (byte) 0);
        b[body] = 0x03;
        b[(short) (body + 1)] = 0x01;
        b[(short) (body + 2)] = 0x02;
        b[(short) (body + 3)] = 0x01;
        Util.arrayCopyNonAtomic(b, W_AMT, b, (short) (body + 12), (short) 12);
        Util.arrayCopyNonAtomic(b, W_SALT, b, (short) (body + 96), (short) 16);

        // The Poly1305 key: the first 32 bytes of block 0.
        Util.arrayFillNonAtomic(b, W_TMP, (short) 32, (byte) 0);
        ChaCha.xorBlock(b, W_NK, 0, b, W_TMP, (short) 32);
        for (short j = 0; j < 16; j++) {
            p[(short) (17 + j)] = (short) (b[(short) (W_TMP + j)] & 0xFF);
            p[(short) (68 + j)] = (short) (b[(short) (W_TMP + 16 + j)] & 0xFF);
        }
        p[20] &= 15;
        p[21] &= 252;
        p[24] &= 15;
        p[25] &= 252;
        p[28] &= 15;
        p[29] &= 252;
        p[32] &= 15;
        Util.arrayFillNonAtomic(b, W_TMP, (short) 32, (byte) 0);

        // Encrypt with blocks 1 to 6.
        short at = body;
        for (short blk = 1; blk <= 5; blk++) {
            ChaCha.xorBlock(b, W_NK, blk, b, at, (short) 64);
            at += 64;
        }
        ChaCha.xorBlock(b, W_NK, 6, b, at, (short) 32);

        // MAC input: associated data (chain id || C) padded to 16, the
        // ciphertext (352, already a whole number of blocks), then both lengths.
        short mac = (short) (W_CD + 14);
        Util.arrayCopyNonAtomic(b, W_CHAIN, b, mac, (short) 8);
        Util.arrayCopyNonAtomic(b, W_C, b, (short) (mac + 8), (short) 32);
        short lens = (short) (body + NOTE_BODY);
        b[lens] = 40;
        b[(short) (lens + 8)] = (byte) 0x60; // 352 = 0x0160, little-endian
        b[(short) (lens + 9)] = 0x01;
        Poly.blocks(p, b, mac, (short) 416);
        Poly.finish(p, b, lens);
        for (short j = 0; j < 102; j++) {
            p[j] = 0;
        }
        Util.arrayFillNonAtomic(b, W_CD, (short) 62, (byte) 0);
    }

    private void commitData(APDU apdu) {
        require(phase() == PHASE_READY && state() == STATE_SEALED, SW_WRONG_STATE);
        sendPart(apdu, fill, F_CD, CD_LEN);
    }

    // ---------------- Check and the LMS signature ----------------

    /**
     * Check: challenge 32.
     * Uses one LMS leaf and answers the 193-byte statement; its signature is
     * read with READ SIGNATURE.
     */
    private void check(APDU apdu) {
        require(phase() == PHASE_READY, SW_WRONG_STATE);
        require(checksLeft() > 0, SW_NO_CHECKS);
        byte[] buf = apdu.getBuffer();
        short in = receive(apdu, (short) 32);
        byte[] s = w;
        Util.arrayFillNonAtomic(s, (short) 0, (short) (C_TMP + 32), (byte) 0);

        byte st = state();
        // Use up the leaf before anything is signed with it.
        short q = Util.getShort(meta, M_NEXT_LEAF);
        Util.setShort(s, C_TMP, (short) (q + 1));
        Nvm.begin();
        Nvm.copy(s, C_TMP, meta, M_NEXT_LEAF, (short) 2);
        Nvm.commit();

        Util.arrayCopyNonAtomic(D_SEAL, (short) 0, s, (short) 0, (short) D_SEAL.length);
        Util.arrayCopyNonAtomic(cardId, (short) 0, s, S_ID, ID_LEN);
        s[S_STATE] = st;
        Util.arrayCopyNonAtomic(meta, M_FILL, s, S_FILL, (short) 4);
        if (st != STATE_BLANK) {
            Util.arrayCopyNonAtomic(fill, F_CHAIN, s, S_CHAIN, (short) 8);
            Util.arrayCopyNonAtomic(fill, F_AMOUNT, s, S_AMT, (short) 12);
            Util.arrayCopyNonAtomic(fill, F_C, s, S_C, (short) 32);
            Util.arrayCopyNonAtomic(fill, F_DIGEST, s, S_DIG, (short) 32);
            Util.arrayCopyNonAtomic(fill, F_MARKER, s, S_M, (short) 32);
        }
        Util.setShort(s, S_LEFT, (short) (LEAVES - q - 1));
        Util.setShort(s, (short) (S_LEAF + 2), q);
        Util.arrayCopyNonAtomic(buf, in, s, S_CHAL, (short) 32);

        // Q = H(I || u32(q) || D_MESG || C || statement), then its checksum.
        byte[] x = ctx;
        rng.nextBytes(x, X_C, (short) 32);
        setLb(q);
        sha.reset();
        sha.update(lb, (short) 0, LB_I);
        lh[0] = D_MESG;
        lh[1] = D_MESG;
        sha.update(lh, (short) 0, (short) 2);
        sha.update(x, X_C, (short) 32);
        sha.doFinal(s, (short) 0, STATEMENT_LEN, x, X_QD);
        short ck = 0;
        for (short i = 0; i < 64; i++) {
            ck += (short) (15 - digit(i));
        }
        Util.setShort(x, (short) (X_QD + 32), (short) (ck << 4));
        Util.setShort(x, X_Q, (short) 0);
        Util.setShort(x, (short) (X_Q + 2), q);
        x[X_VALID] = 1;

        send(apdu, s, (short) 0, STATEMENT_LEN);
        Util.arrayFillNonAtomic(s, (short) 0, (short) (C_TMP + 32), (byte) 0);
    }

    /**
     * READ SIGNATURE: bytes P1P2.. of the last Check's RFC 8554 signature
     * (2,508 bytes), as many as the reader's Le asks. Each one-time chain is
     * computed when it is read.
     */
    private void readSignature(APDU apdu) {
        require(ctx[X_VALID] == 1, SW_WRONG_STATE);
        byte[] buf = apdu.getBuffer();
        short at = Util.getShort(buf, ISO7816.OFFSET_P1);
        require(at >= 0 && at <= SIG_LEN, ISO7816.SW_INCORRECT_P1P2);
        short le = apdu.setOutgoing();
        short len = (short) (SIG_LEN - at);
        if (le < len) {
            len = le;
        }
        apdu.setOutgoingLength(len);
        short end = (short) (at + len);
        short q = Util.getShort(ctx, (short) (X_Q + 2));
        setLb(q);
        // The signature as elements: header 0..40, chains 40..2184, type 2184..2188, path 2188..2508.
        short pos = at;
        while (pos < end) {
            short start;
            short size;
            if (pos < 40) {
                start = 0;
                size = 40;
                Util.arrayFillNonAtomic(lh, (short) 0, (short) 8, (byte) 0);
                Util.setShort(lh, (short) 2, q);
                lh[7] = LMOTS_SHA256_N32_W4;
                // C goes after the two type words; lh has room for 64 bytes.
                Util.arrayCopyNonAtomic(ctx, X_C, lh, (short) 8, (short) 32);
            } else if (pos < 2184) {
                short i = (short) ((short) (pos - 40) >> 5);
                start = (short) (40 + (short) (i << 5));
                size = 32;
                chain(i, digit(i));
                Util.arrayCopyNonAtomic(lb, LB_TMP, lh, (short) 0, (short) 32);
            } else if (pos < 2188) {
                start = 2184;
                size = 4;
                Util.arrayFillNonAtomic(lh, (short) 0, (short) 4, (byte) 0);
                lh[3] = LMS_SHA256_M32_H10;
            } else {
                short k = (short) ((short) (pos - 2188) >> 5);
                start = (short) (2188 + (short) (k << 5));
                size = 32;
                short node = (short) ((short) (LEAVES + q) >> k);
                readNode((short) (node ^ 1), lh, (short) 0);
            }
            short from = (short) (pos - start);
            short n = (short) (size - from);
            if (n > (short) (end - pos)) {
                n = (short) (end - pos);
            }
            apdu.sendBytesLong(lh, from, n);
            pos += n;
        }
        Util.arrayFillNonAtomic(lh, (short) 0, (short) 64, (byte) 0);
        Util.arrayFillNonAtomic(lb, LB_TMP, (short) 32, (byte) 0);
    }

    /** Digit i (0..66) of Q || checksum, four bits each. */
    private short digit(short i) {
        byte v = ctx[(short) (X_QD + (i >> 1))];
        return (short) (((i & 1) == 0 ? (v >> 4) : v) & 0x0F);
    }

    /** lb = I || u32(q). */
    private void setLb(short q) {
        Util.arrayCopyNonAtomic(cardId, (short) 0, lb, (short) 0, ID_LEN);
        Util.setShort(lb, LB_Q, (short) 0);
        Util.setShort(lb, (short) (LB_Q + 2), q);
    }

    /** Chain i of the leaf in lb, run `steps` steps from its private value; the result is in lb[23..54]. */
    private void chain(short i, short steps) {
        byte[] l = lb;
        Util.setShort(l, LB_I, i);
        l[LB_J] = (byte) 0xFF;
        Util.arrayCopyNonAtomic(lmsSeed, (short) 0, l, LB_TMP, (short) 32);
        chainStep();
        for (short j = 0; j < steps; j++) {
            l[LB_J] = (byte) j;
            chainStep();
        }
    }

    private void chainStep() {
        sha.reset();
        sha.doFinal(lb, (short) 0, LB_LEN, lb, LB_TMP);
    }

    // ---------------- the LMS tree ----------------

    /** Reads tree node r (2..2047) into out[off..off+32). */
    private void readNode(short r, byte[] out, short off) {
        short idx = (short) (r - 2);
        if (idx < NODES_PER_ARRAY) {
            Util.arrayCopyNonAtomic(tree0, (short) (idx << 5), out, off, (short) 32);
        } else {
            Util.arrayCopyNonAtomic(tree1, (short) ((short) (idx - NODES_PER_ARRAY) << 5), out, off, (short) 32);
        }
    }

    /** Writes tree node r (1..2047) from src[off..off+32); the root goes into the public key. */
    private void writeNode(short r, byte[] src, short off) {
        if (r == 1) {
            Nvm.copy(src, off, pub, (short) 24, (short) 32);
            return;
        }
        short idx = (short) (r - 2);
        if (idx < NODES_PER_ARRAY) {
            Nvm.copy(src, off, tree0, (short) (idx << 5), (short) 32);
        } else {
            Nvm.copy(src, off, tree1, (short) ((short) (idx - NODES_PER_ARRAY) << 5), (short) 32);
        }
    }

    /**
     * GENERATE (loading only): makes the next P1 leaves (1 to 16) of the LMS
     * tree and every inner node they complete. Answers how many leaves are made.
     */
    private void generate(APDU apdu) {
        require(phase() == PHASE_LOADING, SW_WRONG_STATE);
        byte[] buf = apdu.getBuffer();
        short count = (short) (buf[ISO7816.OFFSET_P1] & 0xFF);
        require(count >= 1 && count <= 16, ISO7816.SW_INCORRECT_P1P2);
        for (short c = 0; c < count; c++) {
            short q = Util.getShort(meta, M_KEYGEN);
            if (q >= LEAVES) {
                break;
            }
            // One atomic write per leaf: its node, the inner nodes it
            // completes, and the count of leaves made.
            Nvm.begin();
            leaf(q);
            Util.setShort(w, (short) 0, (short) (q + 1));
            Nvm.copy(w, (short) 0, meta, M_KEYGEN, (short) 2);
            Nvm.commit();
        }
        Util.setShort(lh, (short) 0, Util.getShort(meta, M_KEYGEN));
        send(apdu, lh, (short) 0, (short) 2);
    }

    /** Makes leaf q's one-time public key, its leaf node, and the inner nodes it completes. */
    private void leaf(short q) {
        byte[] h = lh;
        setLb(q);
        // K = H(I || u32(q) || D_PBLC || y_0 || ... || y_66), each y_i at the end of its chain.
        shaK.reset();
        shaK.update(lb, (short) 0, LB_I);
        h[0] = D_PBLC;
        h[1] = D_PBLC;
        shaK.update(h, (short) 0, (short) 2);
        for (short i = 0; i < OTS_CHAINS; i++) {
            chain(i, (short) 15);
            shaK.update(lb, LB_TMP, (short) 32);
        }
        shaK.doFinal(h, (short) 0, (short) 0, h, (short) 32);
        Util.arrayFillNonAtomic(lb, LB_TMP, (short) 32, (byte) 0);
        // T[r] = H(I || u32(r) || D_LEAF || K) for r = 2^h + q.
        short r = (short) (LEAVES + q);
        nodeHash(r, D_LEAF, (short) 32);
        writeNode(r, h, (short) 0);
        // Each right child completes its parent: T[p] = H(I || u32(p) || D_INTR || T[2p] || T[2p+1]).
        while ((r & 1) == 1 && r > 1) {
            Util.arrayCopyNonAtomic(h, (short) 0, h, (short) 32, (short) 32);
            readNode((short) (r - 1), w, (short) 0);
            r = (short) (r >> 1);
            sha.reset();
            sha.update(cardId, (short) 0, ID_LEN);
            Util.setShort(w, (short) 32, (short) 0);
            Util.setShort(w, (short) 34, r);
            w[36] = D_INTR;
            w[37] = D_INTR;
            sha.update(w, (short) 32, (short) 6);
            sha.update(w, (short) 0, (short) 32);
            sha.doFinal(h, (short) 32, (short) 32, h, (short) 0);
            writeNode(r, h, (short) 0);
        }
    }

    /** lh[0..32) = H(I || u32(r) || d || d || lh[32..32+len)). */
    private void nodeHash(short r, byte d, short len) {
        byte[] h = lh;
        sha.reset();
        sha.update(cardId, (short) 0, ID_LEN);
        Util.setShort(w, (short) 0, (short) 0);
        Util.setShort(w, (short) 2, r);
        w[4] = d;
        w[5] = d;
        sha.update(w, (short) 0, (short) 6);
        sha.doFinal(h, (short) 32, len, h, (short) 0);
    }

    /** WRITE CERT (loading only): writes up to 512 bytes of command data at offset P1P2 of the certificate, atomically. */
    private void writeCert(APDU apdu) {
        require(phase() == PHASE_LOADING, SW_WRONG_STATE);
        byte[] buf = apdu.getBuffer();
        short at = Util.getShort(buf, ISO7816.OFFSET_P1);
        short got = apdu.setIncomingAndReceive();
        short total = apdu.getIncomingLength();
        require(at >= 0 && total > 0 && total <= CERT_PART && (short) (cert.length - at) >= total,
                ISO7816.SW_WRONG_LENGTH);
        short in = apdu.getOffsetCdata();
        short done = 0;
        while (true) {
            Util.arrayCopyNonAtomic(buf, in, w, done, got);
            done += got;
            if (done >= total) {
                break;
            }
            got = apdu.receiveBytes(in);
        }
        Nvm.begin();
        Nvm.copy(w, (short) 0, cert, at, total);
        Nvm.commit();
    }

    /**
     * FINISH (loading only): data is the certificate's length. Needs the whole
     * LMS tree. The card then leaves loading for good and is blank at fill 0.
     */
    private void finish(APDU apdu) {
        require(phase() == PHASE_LOADING && Util.getShort(meta, M_KEYGEN) == LEAVES, SW_WRONG_STATE);
        byte[] buf = apdu.getBuffer();
        short in = receive(apdu, (short) 2);
        short len = Util.getShort(buf, in);
        require(len > 0 && len <= (short) cert.length, ISO7816.SW_WRONG_DATA);
        Util.setShort(w, (short) 0, len);
        Nvm.begin();
        Nvm.copy(w, (short) 0, meta, M_CERT_LEN, (short) 2);
        Nvm.setByte(meta, M_PHASE, PHASE_READY);
        Nvm.commit();
    }

    // ---------------- Open and Refill ----------------

    /**
     * Open: no data. Marks the fill opened, then answers
     * fill 4 || card random 32 || writer nonce 32: the bearer takes the
     * fill's seed material, and the phone rebuilds the key and the coin from it.
     */
    private void open(APDU apdu) {
        byte st = state();
        require(phase() == PHASE_READY && (st == STATE_SEALED || st == STATE_OPENED), SW_WRONG_STATE);
        if (st == STATE_SEALED) {
            Nvm.begin();
            Nvm.setByte(meta, M_STATE, STATE_OPENED);
            Nvm.commit();
        }
        byte[] b = w;
        Util.arrayCopyNonAtomic(meta, M_FILL, b, (short) 0, (short) 4);
        Util.arrayCopyNonAtomic(fill, F_RAND, b, (short) 4, (short) 64);
        send(apdu, b, (short) 0, OPEN_OUT);
        Util.arrayFillNonAtomic(b, (short) 0, OPEN_OUT, (byte) 0);
    }

    /** Refill: no data. On an opened fill, wipes the fill and returns to blank. */
    private void refill(APDU apdu) {
        require(phase() == PHASE_READY && state() == STATE_OPENED, SW_WRONG_STATE);
        // One atomic write: the fill wiped (copied over from zeroed RAM) and the state blank.
        Util.arrayFillNonAtomic(w, (short) 0, FILL_LEN, (byte) 0);
        Nvm.begin();
        Nvm.copy(w, (short) 0, fill, (short) 0, FILL_LEN);
        Nvm.setByte(meta, M_STATE, STATE_BLANK);
        Nvm.commit();
    }

    // ---------------- ints ----------------

    private static int getInt(byte[] b, short o) {
        return ((int) Util.getShort(b, o) << 16) | (Util.getShort(b, (short) (o + 2)) & 0xFFFF);
    }

    private static void setInt(byte[] b, short o, int v) {
        Util.setShort(b, o, (short) (v >>> 16));
        Util.setShort(b, (short) (o + 2), (short) v);
    }
}
