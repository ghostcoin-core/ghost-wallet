package ghostcard.host;

import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.TerminalFactory;

/**
 * Runs the applet on a real card over PC/SC, timing each command and checking
 * every answer as a phone would.
 *
 *   info           what the card says about itself
 *   load           makes the whole LMS tree (about 50 minutes on a J3R180; resumes where it stopped)
 *   certify        writes a test certificate and finishes loading (a test card only)
 *   run [fills]    Make, Check, Open and Refill for that many fills (default 3), timed
 *
 * Set GHOST_MAX_ANSWER to the reader's longest answer (default 256, a USB contact reader's limit).
 */
public final class RealCard {

    static final SecureRandom RNG = new SecureRandom();
    static CardChannel channel;

    public static void main(String[] args) throws Exception {
        TerminalFactory tf = TerminalFactory.getDefault();
        CardTerminal term = tf.terminals().list().get(0);
        Card card = term.connect("*");
        System.out.println("reader: " + term.getName() + ", protocol " + card.getProtocol());
        channel = card.getBasicChannel();
        int maxAnswer = Integer.parseInt(System.getenv().getOrDefault("GHOST_MAX_ANSWER", "256"));
        CardClient c = new CardClient(cmd -> {
            try {
                return channel.transmit(new CommandAPDU(cmd)).getBytes();
            } catch (Exception e) {
                throw new IllegalStateException(e);
            }
        }, maxAnswer);
        c.select();
        String mode = args.length > 0 ? args[0] : "info";
        switch (mode) {
            case "info" -> info(c);
            case "load" -> load(c);
            case "certify" -> certify(c);
            case "run" -> run(c, args.length > 1 ? Integer.parseInt(args[1]) : 3);
            default -> throw new IllegalArgumentException(mode);
        }
        card.disconnect(false);
    }

    static void info(CardClient c) {
        CardClient.Identity id = c.identify();
        System.out.printf("card id %s, phase %d, state %d, fill %d, checks left %d, leaves made %d, certificate %d bytes%n",
                java.util.HexFormat.of().formatHex(id.cardId), id.phase, id.state, id.fill, id.checksLeft,
                id.leavesMade, id.certLen);
    }

    static void load(CardClient c) {
        int made = c.identify().leavesMade;
        long start = System.nanoTime();
        int startMade = made;
        while (made < 1024) {
            long t = System.nanoTime();
            made = c.generate(1);
            double ms = (System.nanoTime() - t) / 1e6;
            if (made % 32 == 0 || made == 1024 || made - startMade <= 3) {
                double per = (System.nanoTime() - start) / 1e9 / (made - startMade);
                System.out.printf("leaves %4d of 1024: last %.0f ms, average %.2f s per leaf, about %.1f min left%n",
                        made, ms, per, per * (1024 - made) / 60);
            }
        }
        System.out.printf("tree made: %d leaves in %.1f min%n", made - startMade, (System.nanoTime() - start) / 60e9);
        System.out.println("public key: " + java.util.HexFormat.of().formatHex(c.publicKey()));
    }

    static void certify(CardClient c) {
        byte[] cert = new byte[7992];
        RNG.nextBytes(cert);
        System.arraycopy(c.identify().cardId, 0, cert, 0, 16);
        System.arraycopy(c.publicKey(), 0, cert, 16, 56);
        c.certify(cert, 240);
        if (!Arrays.equals(c.certificate(), cert)) {
            throw new IllegalStateException("certificate read back differs");
        }
        info(c);
    }

    static byte[] rand(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    static double since(long t) {
        return (System.nanoTime() - t) / 1e6;
    }

    static void need(boolean ok, String what) {
        if (!ok) {
            throw new IllegalStateException(what);
        }
    }

    static void run(CardClient c, int fills) {
        byte[] pub = c.publicKey();
        byte[] cardId = c.identify().cardId;
        List<double[]> rows = new ArrayList<>();
        for (int n = 0; n < fills; n++) {
            byte[] code = rand(20);
            byte[] nonce = rand(32);
            byte[] amount = new byte[12];
            amount[4] = 0x0d;
            amount[5] = (byte) 0xe0;
            byte[] chain = {0, 0, 0, 0, 0, 0, 0, 1};

            long t = System.nanoTime();
            byte[] made = c.make(amount, chain, nonce, Ghost.codeHash(code));
            double tMake = since(t);
            long fill = Ghost.u32(made, 0);
            byte[] commitment = Arrays.copyOfRange(made, 4, 36);
            byte[] commitData = Arrays.copyOfRange(made, 36, 466);

            // The writer's Check, as the app runs it right after Make.
            byte[] challenge = rand(32);
            t = System.nanoTime();
            byte[][] r = c.check(challenge, null);
            double tCheck = since(t);
            need(Ghost.lmsVerify(pub, r[0], r[1]), "the statement's LMS signature verifies");
            Ghost.Statement s = new Ghost.Statement(r[0]);
            need(s.state == 1 && s.fill == fill, "sealed at this fill");
            need(Arrays.equals(s.commitment, commitment), "statement commitment");
            need(Arrays.equals(s.digest, Ghost.sha256(commitData)), "statement digest");
            need(Arrays.equals(s.challenge, challenge), "statement challenge");

            // A receiver's Check confirming the open code.
            challenge = rand(32);
            t = System.nanoTime();
            r = c.check(challenge, Ghost.confirmation(Ghost.codeHash(code), challenge));
            double tCheckCode = since(t);
            need(Ghost.lmsVerify(pub, r[0], r[1]), "the second statement verifies");
            need(new Ghost.Statement(r[0]).confirmation == 1, "the open code is confirmed");

            challenge = rand(32);
            t = System.nanoTime();
            byte[] opened = c.open(code, challenge);
            double tOpen = since(t);
            byte[] release = Ghost.openRelease(cardId, code, challenge, fill, opened);
            need(Arrays.equals(Arrays.copyOfRange(release, 32, 64), nonce), "Open releases the writer nonce");
            Ghost.Coin coin = Ghost.coin(Arrays.copyOf(release, 32), nonce, Arrays.copyOfRange(commitData, 34, 50),
                    Arrays.copyOfRange(commitData, 53, 62), amount, chain);
            need(Arrays.equals(coin.commitData, commitData), "the opener recomputes the card's commit data bit for bit");
            need(Arrays.equals(coin.commitment, commitment), "and its commitment");
            need(Arrays.equals(coin.marker, s.marker), "and its marker");

            t = System.nanoTime();
            c.refill(code);
            double tRefill = since(t);
            need(c.identify().state == 0, "blank after Refill");
            System.out.printf("fill %d: Make %.0f ms, Check %.0f ms, Check with code %.0f ms, Open %.0f ms, Refill %.0f ms (all answers verified)%n",
                    fill, tMake, tCheck, tCheckCode, tOpen, tRefill);
            rows.add(new double[] {tMake, tCheck, tCheckCode, tOpen, tRefill});
        }
        String[] names = {"Make", "Check", "Check with open code", "Open", "Refill"};
        double[] budget = {10000, 3000, 3000, 3000, 3000};
        System.out.println("median over " + fills + " fills, this reader:");
        for (int i = 0; i < names.length; i++) {
            final int k = i;
            double[] v = rows.stream().mapToDouble(x -> x[k]).sorted().toArray();
            double med = v[v.length / 2];
            System.out.printf("  %-22s %6.0f ms  (budget %5.0f ms)  %s%n", names[i], med, budget[i],
                    med <= budget[i] ? "pass" : "OVER");
        }
        info(c);
    }
}
