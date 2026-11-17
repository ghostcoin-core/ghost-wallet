package ghostcard.host;

import java.io.ByteArrayOutputStream;
import java.util.Arrays;

/**
 * Talks to the Ghost card applet: builds each command, reads long answers in
 * parts, and returns the answer bytes. The same client drives jcardsim in the
 * tests and a real card over PC/SC.
 */
public final class CardClient {

    /** Sends one command APDU and returns its answer: data followed by the two status bytes. */
    public interface Link {
        byte[] transmit(byte[] command);
    }

    /** A status word other than 9000. */
    public static final class CardError extends RuntimeException {
        public final int sw;

        CardError(int ins, int sw) {
            super(String.format("INS %02X answered %04X", ins, sw));
            this.sw = sw;
        }
    }

    public static final byte[] AID = hex("A000000847474341524401");
    public static final int SW_WRONG_STATE = 0x6985;
    public static final int SW_NO_CHECKS = 0x6984;
    public static final int SIGNATURE_LEN = 2508;
    public static final int STATEMENT_LEN = 193;

    private final Link link;
    /** The longest answer asked for in one command (the USB reader takes 256). */
    private final int maxAnswer;

    public CardClient(Link link, int maxAnswer) {
        this.link = link;
        this.maxAnswer = maxAnswer;
    }

    public static byte[] hex(String s) {
        return java.util.HexFormat.of().parseHex(s);
    }

    /** Builds a command APDU, short or extended as the lengths need. */
    static byte[] apdu(int cla, int ins, int p1, int p2, byte[] data, int le) {
        int lc = data == null ? 0 : data.length;
        boolean ext = lc > 255 || le > 256;
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.write(cla);
        o.write(ins);
        o.write(p1);
        o.write(p2);
        if (lc > 0) {
            if (ext) {
                o.write(0);
                o.write(lc >> 8);
                o.write(lc);
            } else {
                o.write(lc);
            }
            o.writeBytes(data);
        }
        if (le > 0) {
            if (ext) {
                if (lc == 0) {
                    o.write(0);
                }
                o.write((le >> 8) & 0xFF);
                o.write(le & 0xFF);
            } else {
                o.write(le == 256 ? 0 : le);
            }
        }
        return o.toByteArray();
    }

    public byte[] send(int ins, int p1p2, byte[] data, int le) {
        byte[] r = link.transmit(apdu(0x80, ins, p1p2 >> 8, p1p2 & 0xFF, data, le));
        int sw = ((r[r.length - 2] & 0xFF) << 8) | (r[r.length - 1] & 0xFF);
        if (sw != 0x9000) {
            throw new CardError(ins, sw);
        }
        return Arrays.copyOf(r, r.length - 2);
    }

    public void select() {
        byte[] r = link.transmit(apdu(0x00, 0xA4, 0x04, 0x00, AID, 0));
        int sw = ((r[r.length - 2] & 0xFF) << 8) | (r[r.length - 1] & 0xFF);
        if (sw != 0x9000) {
            throw new CardError(0xA4, sw);
        }
    }

    /** Reads `total` bytes of a stored answer with a part-reading command (offset in P1P2). */
    private byte[] readParts(int ins, int total) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        while (o.size() < total) {
            int n = Math.min(maxAnswer, total - o.size());
            byte[] part = send(ins, o.size(), null, n);
            if (part.length == 0) {
                throw new IllegalStateException("empty part");
            }
            o.writeBytes(part);
        }
        return o.toByteArray();
    }

    // ---------------- commands ----------------

    public Identity identify() {
        return new Identity(send(0x10, 0, null, 29));
    }

    public byte[] certificate() {
        return readParts(0x12, identify().certLen);
    }

    public byte[] publicKey() {
        return send(0x14, 0, null, 56);
    }

    /** Make: answers fill 4 || commitment 32 || commit data 430. */
    public byte[] make(byte[] amount12, byte[] chainId8, byte[] writerNonce) {
        byte[] in = concat(amount12, chainId8, writerNonce);
        int want = Math.min(maxAnswer, 466);
        byte[] first = send(0x20, 0, in, want);
        if (first.length == 466) {
            return first;
        }
        // The rest of the commit data, read again with COMMIT DATA.
        int have = first.length - 36;
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        o.writeBytes(first);
        while (have < 430) {
            byte[] part = send(0x22, have, null, Math.min(maxAnswer, 430 - have));
            o.writeBytes(part);
            have += part.length;
        }
        return o.toByteArray();
    }

    public byte[] commitData() {
        return readParts(0x22, 430);
    }

    /** Check: the statement and its signature, read in parts. */
    public byte[][] check(byte[] challenge) {
        byte[] statement = send(0x30, 0, challenge, STATEMENT_LEN);
        byte[] signature = readParts(0x32, SIGNATURE_LEN);
        return new byte[][] {statement, signature};
    }

    /** Check without reading the signature (it can then never be read: the next command ends it). */
    public byte[] checkStatementOnly(byte[] challenge) {
        return send(0x30, 0, challenge, STATEMENT_LEN);
    }

    public byte[] readSignature(int offset, int len) {
        return send(0x32, offset, null, len);
    }

    /** Open: answers fill 4 || card random 32 || writer nonce 32. */
    public byte[] open() {
        return send(0x40, 0, null, 68);
    }

    public void refill() {
        send(0x50, 0, null, 0);
    }

    /** GENERATE: makes up to `count` more LMS leaves; answers the number made so far. */
    public int generate(int count) {
        byte[] r = send(0x60, count << 8, null, 2);
        return ((r[0] & 0xFF) << 8) | (r[1] & 0xFF);
    }

    public void writeCert(int offset, byte[] data) {
        send(0x64, offset, data, 0);
    }

    public void finish(int certLen) {
        send(0x66, 0, new byte[] {(byte) (certLen >> 8), (byte) certLen}, 0);
    }

    /** Writes a certificate in parts of at most `part` bytes, then finishes loading. */
    public void certify(byte[] cert, int part) {
        for (int at = 0; at < cert.length; at += part) {
            writeCert(at, Arrays.copyOfRange(cert, at, Math.min(cert.length, at + part)));
        }
        finish(cert.length);
    }

    public static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream o = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            o.writeBytes(p);
        }
        return o.toByteArray();
    }

    /** Identify's answer. */
    public static final class Identity {
        public final int format;
        public final int phase;
        public final int state;
        public final byte[] cardId;
        public final long fill;
        public final int checksLeft;
        public final int leavesMade;
        public final int certLen;

        Identity(byte[] r) {
            format = r[0];
            phase = r[1];
            state = r[2];
            cardId = Arrays.copyOfRange(r, 3, 19);
            fill = ((r[19] & 0xFFL) << 24) | ((r[20] & 0xFF) << 16) | ((r[21] & 0xFF) << 8) | (r[22] & 0xFF);
            checksLeft = ((r[23] & 0xFF) << 8) | (r[24] & 0xFF);
            leavesMade = ((r[25] & 0xFF) << 8) | (r[26] & 0xFF);
            certLen = ((r[27] & 0xFF) << 8) | (r[28] & 0xFF);
        }
    }
}
