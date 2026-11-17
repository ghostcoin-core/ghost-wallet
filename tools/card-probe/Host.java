import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HexFormat;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import javax.smartcardio.TerminalFactory;

/** Drives the probe applet over PC/SC, times each test and checks answers. */
public class Host {
    static final HexFormat HEX = HexFormat.of();
    static CardChannel ch;

    static ResponseAPDU tx(int ins, int p1p2, byte[] data, int le) throws Exception {
        CommandAPDU c = data == null
                ? (le > 0 ? new CommandAPDU(0x80, ins, p1p2 >> 8, p1p2 & 0xFF, le) : new CommandAPDU(0x80, ins, p1p2 >> 8, p1p2 & 0xFF))
                : (le > 0 ? new CommandAPDU(0x80, ins, p1p2 >> 8, p1p2 & 0xFF, data, le) : new CommandAPDU(0x80, ins, p1p2 >> 8, p1p2 & 0xFF, data));
        ResponseAPDU r = ch.transmit(c);
        if (r.getSW() != 0x9000) {
            throw new RuntimeException(String.format("INS %02X SW %04X", ins, r.getSW()));
        }
        return r;
    }

    /** Median wall time in ms of `reps` runs of one command. */
    static double time(int ins, int p1p2, int reps) throws Exception {
        double[] t = new double[reps];
        for (int i = 0; i < reps; i++) {
            long s = System.nanoTime();
            tx(ins, p1p2, null, 0);
            t[i] = (System.nanoTime() - s) / 1e6;
        }
        Arrays.sort(t);
        return t[reps / 2];
    }

    public static void main(String[] args) throws Exception {
        TerminalFactory tf = TerminalFactory.getDefault();
        CardTerminal term = tf.terminals().list().get(0);
        System.out.println("reader: " + term.getName());
        Card card = term.connect("*");
        System.out.println("protocol: " + card.getProtocol());
        System.out.println("ATR: " + HEX.formatHex(card.getATR().getBytes()));
        ch = card.getBasicChannel();
        ResponseAPDU sel = ch.transmit(new CommandAPDU(0x00, 0xA4, 0x04, 0x00, HEX.parseHex("A00000084750524F4201")));
        System.out.printf("select: %04X%n", sel.getSW());
        String mode = args.length > 0 ? args[0] : "all";

        byte[] info = tx(0x01, 0, null, 256).getData();
        String[] names = {"SHA-256", "SHA-512", "SHA3-256", "SHA3-512", "AES-CBC", "AES-CTR", "AES-GCM", "AES-CCM",
            "AES-256 key", "AES-CMAC", "HMAC-SHA256", "SecureRandom", "TRNG", "KeyGen RNG", "RAM int arrays"};
        for (int i = 0; i < names.length; i++) {
            System.out.printf("  %-20s %s%n", names[i], info[i] == 1 ? "yes" : info[i] == 0 ? "no" : "error");
        }
        printMem(info, names.length);

        double nop = time(0x00, 0, 30);
        System.out.printf("APDU round trip (no-op): %.2f ms%n", nop);

        // SHA-256: 1,000 calls over 55 bytes (the LMS chain input size)
        double sha = time(0x10, 1000, 3);
        System.out.printf("SHA-256 x1000 (55-byte input): %.0f ms total, %.3f ms per call%n", sha - nop, (sha - nop) / 1000);

        // Keccak correctness then speed
        byte[] msg = "ghost-card-probe".getBytes();
        byte[] want = MessageDigest.getInstance("SHA3-256").digest(msg);
        byte[] gotS = tx(0x22, 0, msg, 32).getData();
        System.out.println("SHA3-256 bytecode (16-bit limbs) matches host: " + Arrays.equals(want, gotS));
        byte[] gotF = tx(0x25, 0, msg, 32).getData();
        System.out.println("SHA3-256 bytecode (unrolled) matches host: " + Arrays.equals(want, gotF));
        double kf1 = time(0x24, 1, 3), kf10 = time(0x24, 10, 3);
        System.out.printf("Keccak-f[1600] bytecode, unrolled: %.0f ms per permutation (1 run %.0f ms, 10 runs %.0f ms)%n",
                (kf10 - kf1) / 9, kf1 - nop, kf10 - nop);
        double cc1 = time(0x31, 1, 3), cc3 = time(0x31, 3, 3);
        System.out.printf("ChaCha20 alone, 7 blocks: %.0f ms%n", (cc3 - cc1) / 2);
        byte[] rf = tx(0x32, 1, null, 32).getData();
        {
            byte[] k = new byte[32], nn = new byte[12], pt = new byte[352], ad = new byte[40];
            for (int i = 0; i < 32; i++) k[i] = (byte) i;
            for (int i = 0; i < 12; i++) nn[i] = (byte) i;
            for (int i = 0; i < 352; i++) pt[i] = (byte) i;
            for (int i = 0; i < 40; i++) ad[i] = (byte) (0xA0 + i);
            Cipher cf = Cipher.getInstance("ChaCha20-Poly1305");
            cf.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "ChaCha20"), new IvParameterSpec(nn));
            cf.updateAAD(ad);
            byte[] ctf = cf.doFinal(pt);
            System.out.println("ChaCha20-Poly1305 unrolled Poly1305 matches host: tag "
                    + Arrays.equals(Arrays.copyOfRange(ctf, 352, 368), Arrays.copyOfRange(rf, 0, 16)));
        }
        double af1 = time(0x32, 1, 3), af3 = time(0x32, 3, 3);
        System.out.printf("ChaCha20-Poly1305 seal, unrolled Poly1305: %.0f ms%n", (af3 - af1) / 2);
        if (mode.equals("fast")) {
            card.disconnect(false);
            return;
        }
        double ks1 = time(0x20, 1, 3), ks10 = time(0x20, 10, 3);
        System.out.printf("Keccak-f[1600] bytecode, 16-bit limbs: %.0f ms per permutation (1 run %.0f ms, 10 runs %.0f ms)%n",
                (ks10 - ks1) / 9, ks1 - nop, ks10 - nop);

        // ChaCha20-Poly1305: check against the host's JCE, then time
        byte[] r = tx(0x30, 1, null, 32).getData();
        byte[] key = new byte[32], nonce = new byte[12], pt = new byte[352], aad = new byte[40];
        for (int i = 0; i < 32; i++) key[i] = (byte) i;
        for (int i = 0; i < 12; i++) nonce[i] = (byte) i;
        for (int i = 0; i < 352; i++) pt[i] = (byte) i;
        for (int i = 0; i < 40; i++) aad[i] = (byte) (0xA0 + i);
        Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "ChaCha20"), new IvParameterSpec(nonce));
        c.updateAAD(aad);
        byte[] ct = c.doFinal(pt);
        boolean tagOk = Arrays.equals(Arrays.copyOfRange(ct, 352, 368), Arrays.copyOfRange(r, 0, 16));
        boolean ctOk = Arrays.equals(Arrays.copyOfRange(ct, 0, 16), Arrays.copyOfRange(r, 16, 32));
        System.out.println("ChaCha20-Poly1305 (352-byte note body + 40-byte AAD = 380-byte sealed note) matches host: ciphertext "
                + ctOk + ", tag " + tagOk);
        double a1 = time(0x30, 1, 3), a3 = time(0x30, 3, 3);
        System.out.printf("ChaCha20-Poly1305 seal: %.0f ms (1 run %.0f ms)%n", (a3 - a1) / 2, a1 - nop);

        // LMS
        byte[] mem = tx(0x02, 0, null, 12).getData();
        System.out.println("after allocating the 2,047-node LMS tree (65,504 bytes):");
        printMem(mem, 0);
        int[] hashes = new int[1];
        double[] st = new double[10];
        int totalH = 0;
        for (int i = 0; i < 10; i++) {
            long s = System.nanoTime();
            byte[] d = tx(0x40, 1, null, 4).getData();
            st[i] = (System.nanoTime() - s) / 1e6 - nop;
            totalH += ((d[0] & 0xFF) << 24) | ((d[1] & 0xFF) << 16) | ((d[2] & 0xFF) << 8) | (d[3] & 0xFF);
        }
        double[] sorted = st.clone();
        Arrays.sort(sorted);
        double avg = Arrays.stream(st).average().getAsDouble();
        System.out.printf("LMS H10/W4 sign (10 signatures): avg %.0f ms, min %.0f ms, max %.0f ms, avg %d SHA-256 calls%n",
                avg, sorted[0], sorted[9], totalH / 10);
        long s = System.nanoTime();
        byte[] leaf = tx(0x41, 2, null, 36).getData();
        double leaf2 = (System.nanoTime() - s) / 1e6 - nop;
        int lh = ((leaf[0] & 0xFF) << 24) | ((leaf[1] & 0xFF) << 16) | ((leaf[2] & 0xFF) << 8) | (leaf[3] & 0xFF);
        System.out.printf("LMS leaf key generation: %.0f ms per leaf (%d SHA-256 calls per leaf)%n", leaf2 / 2, lh / 2);
        System.out.printf("LMS H10 key generation estimate (1,024 leaves + 1,023 inner nodes): %.1f minutes%n",
                (leaf2 / 2 * 1024 + 1023 * (sha - nop) / 1000 * 2) / 60000);

        // Extended length
        try {
            byte[] big = new byte[1000];
            for (int i = 0; i < big.length; i++) big[i] = (byte) (i * 7);
            ResponseAPDU er = ch.transmit(new CommandAPDU(0x80, 0x50, 0x03, 0x00, big, 768));
            byte[] d = er.getData();
            boolean hashOk = er.getSW() == 0x9000
                    && Arrays.equals(Arrays.copyOf(d, 32), MessageDigest.getInstance("SHA-256").digest(big));
            System.out.printf("extended APDU: SW %04X, 1000 bytes in hashed right: %s, %d bytes out%n", er.getSW(), hashOk, d.length);
        } catch (Exception e) {
            System.out.println("extended APDU: failed: " + e);
        }
        card.disconnect(false);
    }

    static void printMem(byte[] b, int o) {
        long p = ((b[o] & 0xFFL) << 24) | ((b[o + 1] & 0xFFL) << 16) | ((b[o + 2] & 0xFFL) << 8) | (b[o + 3] & 0xFFL);
        long tr = ((b[o + 4] & 0xFFL) << 24) | ((b[o + 5] & 0xFFL) << 16) | ((b[o + 6] & 0xFFL) << 8) | (b[o + 7] & 0xFFL);
        long td = ((b[o + 8] & 0xFFL) << 24) | ((b[o + 9] & 0xFFL) << 16) | ((b[o + 10] & 0xFFL) << 8) | (b[o + 11] & 0xFFL);
        System.out.printf("  free persistent %d bytes, free RAM (reset) %d bytes, free RAM (deselect) %d bytes%n", p, tr, td);
    }
}
