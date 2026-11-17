package ghostcard;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghostcard.host.CardClient;
import ghostcard.host.CardClient.CardError;
import ghostcard.host.CardClient.Identity;
import ghostcard.host.Ghost;
import ghostcard.host.Ghost.Statement;

/**
 * The applet's tests on jcardsim: every command, every refusal in a wrong
 * state, a power cut at every persistent write, Ghost's vectors bit for bit,
 * and every LMS signature checked with Bouncy Castle's RFC 8554 verifier.
 *
 * Usage: CardTests <vectors.txt> [test name ...]
 */
public final class CardTests {

    static final HexFormat HEX = HexFormat.of();
    static final SecureRandom RNG = new SecureRandom();
    static final int CERT_LEN = 7992;
    static Path vectorsPath;

    interface Test {
        void run() throws Exception;
    }

    public static void main(String[] args) throws Exception {
        vectorsPath = Path.of(args[0]);
        // jcardsim's random source is a fixed sequence unless told otherwise,
        // which would give every simulated card the same id and LMS key.
        System.setProperty("com.licel.jcardsim.randomdata.secure", "1");
        Map<String, Test> tests = new LinkedHashMap<>();
        tests.put("vectors: Make gives Ghost's F, commitment, marker and commit data bit for bit", CardTests::vectors);
        tests.put("host reference matches Ghost's vectors", CardTests::referenceMatchesVectors);
        tests.put("the phone's vectors: every signature verifies, every statement as recorded",
                () -> PhoneVectors.run(vectorsPath.resolveSibling("phone-vectors.txt"), readVectors()));
        tests.put("a full life: two fills, every answer checked", CardTests::fullLife);
        tests.put("every LMS signature verifies with an RFC 8554 verifier, and only for its statement", CardTests::signatures);
        tests.put("signatures read in parts of any size are the same bytes", CardTests::signatureParts);
        tests.put("a signature can only be read until the next command", CardTests::signatureContext);
        tests.put("loading: refusals before the card is ready", CardTests::loadingRefusals);
        tests.put("blank: refusals", CardTests::blankRefusals);
        tests.put("sealed: refusals", CardTests::sealedRefusals);
        tests.put("opened: refusals, and Open again gives the same seed material", CardTests::openedRefusals);
        tests.put("open codes: confirmation right, wrong, not asked", CardTests::codeConfirmation);
        tests.put("an earlier fill's code opens nothing", CardTests::oldCodeOpensNothing);
        tests.put("seal checks count down; Make needs 16; Check stops at 0; Open still works", CardTests::checksCountDown);
        tests.put("Make refuses with 15 checks left", CardTests::makeNeedsSixteen);
        tests.put("malformed commands are refused", CardTests::malformed);
        tests.put("short answers: a 256-byte reader gets the same Make", CardTests::shortAnswers);
        tests.put("no answer ever carries the key, the card random or the LMS seed", CardTests::secretsNeverLeave);
        tests.put("power cut at every write of Make", CardTests::tearMake);
        tests.put("power cut at every write of Check", CardTests::tearCheck);
        tests.put("power cut at every write of Open", CardTests::tearOpen);
        tests.put("power cut at every write of Refill", CardTests::tearRefill);
        tests.put("power cut at every write of loading (Generate, certificate, Finish)", CardTests::tearLoading);

        List<String> only = Arrays.asList(args).subList(1, args.length);
        int failed = 0;
        int ran = 0;
        for (Map.Entry<String, Test> t : tests.entrySet()) {
            if (!only.isEmpty() && only.stream().noneMatch(o -> t.getKey().contains(o))) {
                continue;
            }
            ran++;
            long start = System.nanoTime();
            try {
                t.getValue().run();
                System.out.printf("ok    %s (%.1f s)%n", t.getKey(), (System.nanoTime() - start) / 1e9);
            } catch (Throwable e) {
                failed++;
                System.out.printf("FAIL  %s%n", t.getKey());
                e.printStackTrace(System.out);
            }
        }
        System.out.printf("%d of %d tests passed%n", ran - failed, ran);
        if (failed > 0 || ran == 0) {
            System.exit(1);
        }
    }

    // ---------------- helpers ----------------

    static void check(boolean ok, String what) {
        if (!ok) {
            throw new AssertionError(what);
        }
    }

    static void same(byte[] a, byte[] b, String what) {
        if (!Arrays.equals(a, b)) {
            throw new AssertionError(what + ": " + (a == null ? "null" : HEX.formatHex(a)) + " != "
                    + (b == null ? "null" : HEX.formatHex(b)));
        }
    }

    static void refused(int sw, Runnable command, String what) {
        try {
            command.run();
        } catch (CardError e) {
            check(e.sw == sw, what + ": expected " + Integer.toHexString(sw) + ", got " + Integer.toHexString(e.sw));
            return;
        }
        throw new AssertionError(what + ": not refused");
    }

    static byte[] rand(int n) {
        byte[] b = new byte[n];
        RNG.nextBytes(b);
        return b;
    }

    static byte[] be(long v, int n) {
        byte[] b = new byte[n];
        for (int i = n - 1; i >= 0; i--) {
            b[i] = (byte) v;
            v >>>= 8;
        }
        return b;
    }

    /** A card on the simulator, loaded (the whole H10 tree made) and certified. */
    static SimCard loadedCard(int maxAnswer) {
        SimCard c = new SimCard(maxAnswer, null);
        int made = 0;
        while (made < 1024) {
            made = c.client.generate(16);
        }
        c.client.certify(testCertificate(c), 255);
        return c;
    }

    /** A stand-in for the issuer's certificate: card id and public key, then filler of a signature's size. */
    static byte[] testCertificate(SimCard c) {
        byte[] cert = new byte[CERT_LEN];
        RNG.nextBytes(cert);
        System.arraycopy(c.client.identify().cardId, 0, cert, 0, 16);
        System.arraycopy(c.client.publicKey(), 0, cert, 16, 56);
        return cert;
    }

    /** What the writer's app keeps for a fill. */
    static final class Fill {
        byte[] code = rand(20);
        byte[] nonce = rand(32);
        byte[] amount = be(RNG.nextLong() & 0x7FFFFFFFFFFFL, 12);
        byte[] chain = rand(8);
        byte[] answer;
        long number;
        byte[] commitment;
        byte[] commitData;
    }

    static Fill make(SimCard c) {
        Fill f = new Fill();
        f.answer = c.client.make(f.amount, f.chain, f.nonce, Ghost.codeHash(f.code));
        check(f.answer.length == 466, "Make answers 466 bytes");
        f.number = Ghost.u32pub(f.answer, 0);
        f.commitment = Arrays.copyOfRange(f.answer, 4, 36);
        f.commitData = Arrays.copyOfRange(f.answer, 36, 466);
        return f;
    }

    /** A Check, verified as a receiver's app does; returns the statement. */
    static Statement verifiedCheck(SimCard c, byte[] pub, byte[] confirmation, byte[] challenge) {
        byte[][] r = c.client.check(challenge, confirmation);
        check(Ghost.lmsVerify(pub, r[0], r[1]), "the seal statement's LMS signature verifies");
        Statement s = new Statement(r[0]);
        same(s.challenge, challenge, "the statement signs this tap's challenge");
        same(s.cardId, c.client.identify().cardId, "the statement's card id");
        return s;
    }

    static Statement verifiedCheck(SimCard c, byte[] pub) {
        return verifiedCheck(c, pub, null, rand(32));
    }

    /** Opens and checks the release against the fill: tag, decryption, and Ghost's coin recomputed. */
    static byte[] openAndVerify(SimCard c, Fill f) {
        byte[] challenge = rand(32);
        byte[] ans = c.client.open(f.code, challenge);
        byte[] release = Ghost.openRelease(c.client.identify().cardId, f.code, challenge, f.number, ans);
        byte[] cardRandom = Arrays.copyOf(release, 32);
        same(Arrays.copyOfRange(release, 32, 64), f.nonce, "Open releases the writer's nonce");
        Ghost.Coin coin = Ghost.coin(cardRandom, f.nonce, Arrays.copyOfRange(f.commitData, 34, 50),
                Arrays.copyOfRange(f.commitData, 53, 62), f.amount, f.chain);
        same(coin.commitData, f.commitData, "the opener recomputes the commit data from the release");
        same(coin.commitment, f.commitment, "the opener recomputes the commitment");
        return release;
    }

    // ---------------- vectors ----------------

    static List<Map<String, byte[]>> readVectors() throws Exception {
        List<Map<String, byte[]>> cases = new ArrayList<>();
        Map<String, byte[]> cur = null;
        for (String line : Files.readAllLines(vectorsPath)) {
            line = line.strip();
            if (line.startsWith("[case")) {
                cur = new LinkedHashMap<>();
                cases.add(cur);
            } else if (cur != null && line.contains("=")) {
                String[] kv = line.split("=", 2);
                cur.put(kv[0].strip(), HEX.parseHex(kv[1].strip()));
            }
        }
        check(cases.size() >= 3, "the vectors file has its cases");
        return cases;
    }

    static void referenceMatchesVectors() throws Exception {
        for (Map<String, byte[]> v : readVectors()) {
            Ghost.Coin coin = Ghost.coin(v.get("card_random"), v.get("writer_nonce"), v.get("salt"),
                    v.get("note_random"), v.get("amount"), v.get("chain_id"));
            same(coin.seed, v.get("seed"), "seed");
            same(coin.fingerprint, v.get("fingerprint"), "F");
            same(coin.commitment, v.get("commitment"), "C");
            same(coin.marker, v.get("marker"), "marker");
            same(coin.commitData, v.get("commit_data"), "commit data");
        }
    }

    static void vectors() throws Exception {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        long fill = 0;
        for (Map<String, byte[]> v : readVectors()) {
            byte[] code = rand(20);
            // Make draws the card random, the salt, then the note nonce's 9 random bytes.
            c.random.push(v.get("card_random"));
            c.random.push(v.get("salt"));
            c.random.push(v.get("note_random"));
            byte[] ans = c.client.make(v.get("amount"), v.get("chain_id"), v.get("writer_nonce"), Ghost.codeHash(code));
            fill++;
            check(Ghost.u32pub(ans, 0) == fill, "fill number");
            same(Arrays.copyOfRange(ans, 4, 36), v.get("commitment"), "Make's commitment");
            same(Arrays.copyOfRange(ans, 36, 466), v.get("commit_data"), "Make's commit data");
            same(Arrays.copyOfRange(ans, 38, 70), v.get("fingerprint"), "F in the commit data");
            same(c.client.commitData(), v.get("commit_data"), "COMMIT DATA gives the same bytes");

            Statement s = verifiedCheck(c, pub);
            check(s.state == GhostCard.STATE_SEALED, "sealed");
            check(s.fill == fill, "statement fill");
            same(s.commitment, v.get("commitment"), "statement commitment");
            same(s.marker, v.get("marker"), "statement marker");
            same(s.digest, Ghost.sha256(v.get("commit_data")), "statement digest is SHA-256 of the commit data");
            same(s.amount, v.get("amount"), "statement amount");
            same(s.chainId, v.get("chain_id"), "statement chain id");

            byte[] challenge = rand(32);
            byte[] release = Ghost.openRelease(c.client.identify().cardId, code, challenge, fill,
                    c.client.open(code, challenge));
            same(Arrays.copyOf(release, 32), v.get("card_random"), "Open releases the card random");
            same(Arrays.copyOfRange(release, 32, 64), v.get("writer_nonce"), "and the writer nonce");
            c.client.refill(code);
        }
        check(c.random.queue.isEmpty(), "Make drew exactly the scripted bytes");
    }

    // ---------------- a whole life ----------------

    static void fullLife() {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        Identity id = c.client.identify();
        check(id.phase == GhostCard.PHASE_READY && id.state == GhostCard.STATE_BLANK, "a loaded card is blank");
        check(id.fill == 0 && id.checksLeft == 1024 && id.leavesMade == 1024 && id.certLen == CERT_LEN, "identify");
        check(c.client.certificate().length == CERT_LEN, "certificate reads back whole");

        Statement blank = verifiedCheck(c, pub);
        check(blank.state == GhostCard.STATE_BLANK && blank.fill == 0, "blank (fill 0)");
        check(Arrays.equals(blank.commitment, new byte[32]) && Arrays.equals(blank.marker, new byte[32]),
                "a blank statement has no coin fields");
        check(blank.checksLeft == 1023 && blank.leaf == 0, "the first check uses leaf 0, 1,023 left");

        for (int n = 1; n <= 2; n++) {
            Fill f = make(c);
            check(f.number == n, "fill number " + n);
            Statement s = verifiedCheck(c, pub);
            check(s.state == GhostCard.STATE_SEALED && s.fill == n, "sealed (fill " + n + ")");
            same(s.commitment, f.commitment, "statement commitment matches Make");
            same(s.digest, Ghost.sha256(f.commitData), "statement digest matches Make's commit data");
            same(s.amount, f.amount, "amount");
            same(s.chainId, f.chain, "chain id");
            openAndVerify(c, f);
            Statement o = verifiedCheck(c, pub);
            check(o.state == GhostCard.STATE_OPENED && o.fill == n, "opened (fill " + n + ")");
            same(o.commitment, f.commitment, "an opened card still says which coin");
            c.client.refill(f.code);
            Statement b = verifiedCheck(c, pub);
            check(b.state == GhostCard.STATE_BLANK && b.fill == n, "blank (fill " + n + ") after Refill");
        }
    }

    // ---------------- signatures ----------------

    static void signatures() {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        Fill f = make(c);
        long lastLeaf = -1;
        for (int i = 0; i < 40; i++) {
            byte[] challenge = rand(32);
            byte[][] r = c.client.check(challenge, null);
            check(Ghost.lmsVerify(pub, r[0], r[1]), "signature " + i + " verifies");
            Statement s = new Statement(r[0]);
            check(s.leaf == lastLeaf + 1, "leaves are used in order, each once");
            check(s.checksLeft == 1023 - s.leaf, "checks left = 1,024 minus the next leaf");
            check(Ghost.u32pub(r[1], 0) == s.leaf, "the signature's q is the statement's leaf");
            lastLeaf = s.leaf;
            // Any change to the statement or the signature fails.
            byte[] bad = r[0].clone();
            bad[RNG.nextInt(bad.length)] ^= (byte) (1 << RNG.nextInt(8));
            check(!Ghost.lmsVerify(pub, bad, r[1]), "an altered statement fails");
            byte[] badSig = r[1].clone();
            badSig[8 + RNG.nextInt(badSig.length - 8)] ^= 1;
            check(!Ghost.lmsVerify(pub, r[0], badSig), "an altered signature fails");
        }
        // Another card's key does not verify this card's statements.
        SimCard other = new SimCard(1024, null);
        while (other.client.generate(16) < 1024) {
            // keep generating
        }
        byte[][] r = c.client.check(rand(32), null);
        check(!Ghost.lmsVerify(other.client.publicKey(), r[0], r[1]), "another card's public key fails");
        check(Ghost.lmsVerify(pub, r[0], r[1]), "its own still verifies");
        check(f.number == 1, "fill");
    }

    static void signatureParts() {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        byte[] statement = c.client.checkStatementOnly(rand(32));
        byte[] whole = c.client.readSignature(0, 2508);
        check(Ghost.lmsVerify(pub, statement, whole), "read whole, it verifies");
        for (int part : new int[] {1, 7, 31, 32, 33, 255, 256, 1000}) {
            java.io.ByteArrayOutputStream o = new java.io.ByteArrayOutputStream();
            while (o.size() < 2508) {
                o.writeBytes(c.client.readSignature(o.size(), Math.min(part, 2508 - o.size())));
            }
            same(o.toByteArray(), whole, "read in parts of " + part);
        }
        check(c.client.readSignature(2508, 1).length == 0, "nothing past the end");
        refused(0x6A86, () -> c.client.readSignature(2509, 1), "offset past the end");
    }

    static void signatureContext() {
        SimCard c = loadedCard(1024);
        refused(CardClient.SW_WRONG_STATE, () -> c.client.readSignature(0, 40), "no Check yet");
        c.client.checkStatementOnly(rand(32));
        c.client.readSignature(0, 40);
        c.client.identify();
        refused(CardClient.SW_WRONG_STATE, () -> c.client.readSignature(0, 40), "after another command");
        c.client.checkStatementOnly(rand(32));
        c.powerCut();
        refused(CardClient.SW_WRONG_STATE, () -> c.client.readSignature(0, 40), "after a power cut");
    }

    // ---------------- states ----------------

    static void loadingRefusals() {
        SimCard c = new SimCard(1024, null);
        Identity id = c.client.identify();
        check(id.phase == GhostCard.PHASE_LOADING && id.leavesMade == 0 && id.certLen == 0, "a new card is loading");
        Fill f = new Fill();
        int s = CardClient.SW_WRONG_STATE;
        refused(s, () -> c.client.make(f.amount, f.chain, f.nonce, Ghost.codeHash(f.code)), "Make while loading");
        refused(s, () -> c.client.checkStatementOnly(rand(32)), "Check while loading");
        refused(s, () -> c.client.open(f.code, rand(32)), "Open while loading");
        refused(s, () -> c.client.refill(f.code), "Refill while loading");
        refused(s, () -> c.client.send(0x22, 0, null, 10), "Commit data while loading");
        refused(s, () -> c.client.send(0x12, 0, null, 10), "Read certificate while loading");
        refused(s, () -> c.client.publicKey(), "Public key before the tree is made");
        refused(s, () -> c.client.finish(10), "Finish before the tree is made");
        refused(0x6A86, () -> c.client.generate(0), "Generate 0");
        refused(0x6A86, () -> c.client.generate(17), "Generate 17");
        check(c.client.generate(3) == 3, "Generate makes leaves");
        while (c.client.generate(16) < 1024) {
            // keep generating
        }
        check(c.client.generate(1) == 1024, "Generate stops at 1,024");
        refused(0x6700, () -> c.client.writeCert(8190, new byte[3]), "certificate past its room");
        refused(0x6A80, () -> c.client.finish(8193), "Finish with a length past the room");
        refused(0x6A80, () -> c.client.finish(0), "Finish with no certificate");
        c.client.certify(testCertificate(c), 512);
        check(c.client.identify().phase == GhostCard.PHASE_READY, "ready");
        refused(s, () -> c.client.generate(1), "Generate after loading");
        refused(s, () -> c.client.writeCert(0, new byte[] {1}), "certificate written after loading");
        refused(s, () -> c.client.finish(10), "Finish twice");
    }

    static void blankRefusals() {
        SimCard c = loadedCard(1024);
        Fill f = new Fill();
        int s = CardClient.SW_WRONG_STATE;
        refused(s, () -> c.client.send(0x22, 0, null, 10), "Commit data on a blank card");
        refused(s, () -> c.client.open(f.code, rand(32)), "Open on a blank card");
        refused(s, () -> c.client.refill(f.code), "Refill on a blank card");
        refused(s, () -> c.client.generate(1), "Generate");
        check(c.client.identify().state == GhostCard.STATE_BLANK, "still blank");
    }

    static void sealedRefusals() {
        SimCard c = loadedCard(1024);
        Fill f = make(c);
        Fill g = new Fill();
        int s = CardClient.SW_WRONG_STATE;
        refused(s, () -> c.client.make(g.amount, g.chain, g.nonce, Ghost.codeHash(g.code)), "a second Make");
        refused(s, () -> c.client.refill(f.code), "Refill on a sealed card, even with its code");
        refused(CardClient.SW_WRONG_CODE, () -> c.client.open(g.code, rand(32)), "Open with a wrong code");
        byte[] near = f.code.clone();
        near[19] ^= 1;
        refused(CardClient.SW_WRONG_CODE, () -> c.client.open(near, rand(32)), "Open with a code one bit off");
        Identity id = c.client.identify();
        check(id.state == GhostCard.STATE_SEALED && id.fill == 1, "still sealed (fill 1)");
        same(c.client.commitData(), f.commitData, "Commit data again");
    }

    static void openedRefusals() {
        SimCard c = loadedCard(1024);
        Fill f = make(c);
        byte[] first = openAndVerify(c, f);
        Fill g = new Fill();
        int s = CardClient.SW_WRONG_STATE;
        refused(s, () -> c.client.make(g.amount, g.chain, g.nonce, Ghost.codeHash(g.code)), "Make on an opened card");
        refused(s, () -> c.client.send(0x22, 0, null, 10), "Commit data on an opened card");
        refused(CardClient.SW_WRONG_CODE, () -> c.client.refill(g.code), "Refill with a wrong code");
        refused(CardClient.SW_WRONG_CODE, () -> c.client.open(g.code, rand(32)), "Open again with a wrong code");
        same(openAndVerify(c, f), first, "Open again gives the same seed material");
        check(c.client.identify().state == GhostCard.STATE_OPENED, "still opened");
    }

    static void codeConfirmation() {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        byte[] ch = rand(32);
        check(verifiedCheck(c, pub, Ghost.confirmation(Ghost.codeHash(rand(20)), ch), ch).confirmation == 2,
                "a blank card confirms no code");
        Fill f = make(c);
        ch = rand(32);
        check(verifiedCheck(c, pub, Ghost.confirmation(Ghost.codeHash(f.code), ch), ch).confirmation == 1, "right code");
        ch = rand(32);
        check(verifiedCheck(c, pub, Ghost.confirmation(Ghost.codeHash(rand(20)), ch), ch).confirmation == 2, "wrong code");
        byte[] old = rand(32);
        byte[] replay = Ghost.confirmation(Ghost.codeHash(f.code), old);
        ch = rand(32);
        check(verifiedCheck(c, pub, replay, ch).confirmation == 2, "a confirmation made for another challenge");
        check(verifiedCheck(c, pub).confirmation == 0, "not asked");
        c.client.open(f.code, rand(32));
        ch = rand(32);
        check(verifiedCheck(c, pub, Ghost.confirmation(Ghost.codeHash(f.code), ch), ch).confirmation == 1,
                "an opened card still confirms its fill's code");
    }

    static void oldCodeOpensNothing() {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        Fill f1 = make(c);
        openAndVerify(c, f1);
        c.client.refill(f1.code);
        refused(CardClient.SW_WRONG_STATE, () -> c.client.open(f1.code, rand(32)), "a blank card opens for no code");
        refused(CardClient.SW_WRONG_STATE, () -> c.client.refill(f1.code), "nor refills");
        Fill f2 = make(c);
        check(f2.number == 2, "fill 2");
        refused(CardClient.SW_WRONG_CODE, () -> c.client.open(f1.code, rand(32)), "fill 1's code on fill 2");
        byte[] ch = rand(32);
        check(verifiedCheck(c, pub, Ghost.confirmation(Ghost.codeHash(f1.code), ch), ch).confirmation == 2,
                "fill 1's code is not confirmed on fill 2");
        openAndVerify(c, f2);
    }

    static void checksCountDown() {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        // Use checks without reading signatures until 17 are left.
        while (c.client.identify().checksLeft > 17) {
            c.client.checkStatementOnly(rand(32));
        }
        Fill f = make(c);
        openAndVerify(c, f);
        c.client.refill(f.code);
        check(verifiedCheck(c, pub).checksLeft == 16, "16 left");
        Fill g = make(c);
        check(g.number == 2, "Make works with 16 checks left");
        // Use every check left: the card stays sealed and still opens.
        while (c.client.identify().checksLeft > 0) {
            Statement s = verifiedCheck(c, pub);
            check(s.state == GhostCard.STATE_SEALED && s.leaf <= 1023, "sealed, leaf in range");
        }
        refused(CardClient.SW_NO_CHECKS, () -> c.client.checkStatementOnly(rand(32)), "Check with none left");
        openAndVerify(c, g);
        c.client.refill(g.code);
        Fill h = new Fill();
        refused(CardClient.SW_NO_CHECKS, () -> c.client.make(h.amount, h.chain, h.nonce, Ghost.codeHash(h.code)),
                "Make with no checks left");
        Identity id = c.client.identify();
        check(id.state == GhostCard.STATE_BLANK && id.checksLeft == 0 && id.fill == 2, "a retired card: blank, 0 left");
    }

    static void makeNeedsSixteen() {
        SimCard c = loadedCard(1024);
        while (c.client.identify().checksLeft > 15) {
            c.client.checkStatementOnly(rand(32));
        }
        Fill f = new Fill();
        refused(CardClient.SW_NO_CHECKS, () -> c.client.make(f.amount, f.chain, f.nonce, Ghost.codeHash(f.code)),
                "Make with 15 checks left");
        check(c.client.identify().state == GhostCard.STATE_BLANK, "still blank");
    }

    static void malformed() {
        SimCard c = loadedCard(1024);
        byte[] r = c.transmit(new byte[] {0x00, 0x10, 0, 0, 0});
        check(r[0] == 0x6E && r[1] == 0, "wrong CLA");
        refused(0x6D00, () -> c.client.send(0x7F, 0, null, 0), "unknown INS");
        refused(0x6700, () -> c.client.send(0x20, 0, new byte[83], 0), "Make with 83 bytes");
        refused(0x6700, () -> c.client.send(0x20, 0, new byte[85], 0), "Make with 85 bytes");
        refused(0x6700, () -> c.client.send(0x30, 0, new byte[31], 0), "Check with 31 bytes");
        refused(0x6700, () -> c.client.send(0x30, 0, new byte[48], 0), "Check with 48 bytes");
        Fill f = make(c);
        refused(0x6700, () -> c.client.send(0x40, 0, new byte[51], 0), "Open with 51 bytes");
        refused(0x6A86, () -> c.client.send(0x22, 431, null, 1), "Commit data past the end");
        check(c.client.identify().state == GhostCard.STATE_SEALED, "still sealed");
        openAndVerify(c, f);
        refused(0x6700, () -> c.client.send(0x50, 0, new byte[21], 0), "Refill with 21 bytes");
    }

    static void shortAnswers() throws Exception {
        SimCard c = loadedCard(256);
        byte[] pub = c.client.publicKey();
        Map<String, byte[]> v = readVectors().get(0);
        byte[] code = rand(20);
        c.random.push(v.get("card_random"));
        c.random.push(v.get("salt"));
        c.random.push(v.get("note_random"));
        byte[] ans = c.client.make(v.get("amount"), v.get("chain_id"), v.get("writer_nonce"), Ghost.codeHash(code));
        same(Arrays.copyOfRange(ans, 36, 466), v.get("commit_data"), "Make read in 256-byte answers");
        Statement s = verifiedCheck(c, pub);
        same(s.digest, Ghost.sha256(v.get("commit_data")), "digest");
        check(c.client.certificate().length == CERT_LEN, "certificate in 256-byte parts");
    }

    // ---------------- secrecy ----------------

    static boolean contains(byte[] hay, byte[] needle) {
        outer:
        for (int i = 0; i + needle.length <= hay.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (hay[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return true;
        }
        return false;
    }

    static void secretsNeverLeave() throws Exception {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        Map<String, byte[]> v = readVectors().get(1);
        byte[] code = rand(20);
        c.random.push(v.get("card_random"));
        c.random.push(v.get("salt"));
        c.random.push(v.get("note_random"));
        c.answers.reset();
        c.client.make(v.get("amount"), v.get("chain_id"), v.get("writer_nonce"), Ghost.codeHash(code));
        for (int i = 0; i < 3; i++) {
            verifiedCheck(c, pub);
        }
        c.client.identify();
        c.client.commitData();
        c.client.certificate();
        c.client.publicKey();
        byte[] ch = rand(32);
        c.client.open(code, ch);
        verifiedCheck(c, pub);
        byte[] all = c.answers.toByteArray();
        byte[] seed = v.get("seed");
        byte[] key = CardClient.concat(new byte[] {0x20}, seed);
        Map<String, byte[]> secrets = new LinkedHashMap<>();
        secrets.put("card random", v.get("card_random"));
        secrets.put("seed bytes", seed);
        secrets.put("s", Ghost.sha3(tag("ghost/secret/v1"), key));
        secrets.put("r", Ghost.sha3(tag("ghost/reveal-secret/v1"), key));
        secrets.put("note key", Ghost.sha3(tag("ghost/note-key/v1"), key));
        secrets.put("LMS seed", c.field("lmsSeed"));
        secrets.put("open code", code);
        for (Map.Entry<String, byte[]> e : secrets.entrySet()) {
            for (int at = 0; at + 8 <= e.getValue().length; at += 8) {
                check(!contains(all, Arrays.copyOfRange(e.getValue(), at, at + 8)),
                        "no answer carries any 8 bytes of the " + e.getKey());
            }
        }
        // The writer nonce is the writer's own; it appears only inside Open's ciphertext, never in the clear.
        check(!contains(all, v.get("writer_nonce")), "the writer nonce is never sent back in the clear");
    }

    static byte[] tag(String t) {
        byte[] b = t.getBytes(java.nio.charset.StandardCharsets.US_ASCII);
        return CardClient.concat(new byte[] {(byte) b.length}, b);
    }

    // ---------------- power cuts ----------------

    /**
     * Runs `command` with the power cut at write 1, 2, ... until it runs to
     * the end; after each cut, `after` checks the card and puts it back.
     * Returns how many cut points the command had.
     */
    static int everyCut(SimCard c, Runnable command, Runnable after) {
        int k = 1;
        while (true) {
            Nvm.arm(k);
            boolean ok;
            try {
                command.run();
                ok = true;
            } catch (CardError e) {
                check(e.sw == 0x6F00 && Nvm.torn, "only the power cut stops the command, got " + Integer.toHexString(e.sw));
                ok = false;
            }
            if (ok) {
                check(!Nvm.torn, "the command finished without a cut");
                Nvm.arm(0);
                return k - 1;
            }
            c.powerCut();
            after.run();
            k++;
        }
    }

    static void tearMake() {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        int[] before = {0};
        int[] after = {0};
        Fill[] last = new Fill[1];
        int points = everyCut(c, () -> {
            Fill f = new Fill();
            last[0] = f;
            f.answer = c.client.make(f.amount, f.chain, f.nonce, Ghost.codeHash(f.code));
        }, () -> {
            Identity id = c.client.identify();
            Fill f = last[0];
            if (id.state == GhostCard.STATE_BLANK) {
                before[0]++;
                check(id.fill == after[0], "a cut before the commit leaves the card blank at its fill");
            } else {
                after[0]++;
                check(id.state == GhostCard.STATE_SEALED && id.fill == after[0], "or sealed at the next fill");
                // The fill is whole: the statement, the commit data and Open agree.
                f.number = id.fill;
                f.commitData = c.client.commitData();
                Statement s = verifiedCheck(c, pub);
                same(s.digest, Ghost.sha256(f.commitData), "digest of the stored commit data");
                f.commitment = s.commitment;
                openAndVerify(c, f);
                c.client.refill(f.code);
            }
        });
        check(points >= 8, "Make has its writes (" + points + ")");
        check(before[0] >= 1 && after[0] >= 0, "cuts before the commit happened");
        check(c.client.identify().state == GhostCard.STATE_SEALED, "the uncut Make sealed the card");
        System.out.printf("      Make: %d cut points, %d left the card blank, %d sealed%n", points, before[0], after[0]);
    }

    static void tearCheck() {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        make(c);
        long[] lastLeaf = {verifiedCheck(c, pub).leaf};
        int points = everyCut(c, () -> {
            c.client.check(rand(32), null);
        }, () -> {
            // The leaf is either still unused or used up; the next Check takes a fresh one and verifies.
            Statement s = verifiedCheck(c, pub);
            check(s.leaf == lastLeaf[0] + 1 || s.leaf == lastLeaf[0] + 2, "no leaf is reused after a cut");
            lastLeaf[0] = s.leaf;
        });
        check(points >= 1, "Check writes the leaf index");
        Statement s = verifiedCheck(c, pub);
        check(s.leaf > lastLeaf[0], "still in order");
        System.out.printf("      Check: %d cut points%n", points);
    }

    static void tearOpen() {
        SimCard c = loadedCard(1024);
        byte[] pub = c.client.publicKey();
        Fill f = make(c);
        int points = everyCut(c, () -> c.client.open(f.code, rand(32)), () -> {
            Identity id = c.client.identify();
            check(id.state == GhostCard.STATE_SEALED || id.state == GhostCard.STATE_OPENED, "sealed or opened");
            check(verifiedCheck(c, pub).state == id.state, "the statement agrees");
            check(id.fill == 1, "same fill");
        });
        check(points >= 1, "Open writes the opened state");
        openAndVerify(c, f);
        System.out.printf("      Open: %d cut points%n", points);
    }

    static void tearRefill() {
        SimCard c = loadedCard(1024);
        Fill f = make(c);
        openAndVerify(c, f);
        int points = everyCut(c, () -> c.client.refill(f.code), () -> {
            Identity id = c.client.identify();
            check(id.fill == 1, "the fill number never goes back");
            if (id.state == GhostCard.STATE_OPENED) {
                openAndVerify(c, f);
            } else {
                check(id.state == GhostCard.STATE_BLANK, "opened or blank");
                Statement s = verifiedCheck(c, c.client.publicKey());
                check(Arrays.equals(s.commitment, new byte[32]) && Arrays.equals(s.digest, new byte[32]),
                        "a blank card shows no coin, whatever a cut left behind");
                // Make the card opened again at a new fill, so the next cut has something to refill.
                Fill g = make(c);
                openAndVerify(c, g);
                f.code = g.code;
                f.number = g.number;
            }
        });
        check(points >= 2, "Refill writes the state and wipes the fill");
        Identity id = c.client.identify();
        check(id.state == GhostCard.STATE_BLANK, "blank after the uncut Refill");
        byte[] fillArea = c.field("fill");
        check(Arrays.equals(fillArea, new byte[fillArea.length]), "the fill is wiped");
        Fill g = make(c);
        check(g.number == id.fill + 1, "the next Make takes the next fill");
        System.out.printf("      Refill: %d cut points%n", points);
    }

    static void tearLoading() {
        SimCard c = new SimCard(1024, null);
        // Cut at every write of the first eight leaves (which complete inner nodes up to height 3).
        // A cut leaves the leaf wholly made or not made at all.
        int total = 0;
        for (int leaf = 0; leaf < 8; leaf++) {
            final int want = leaf + 1;
            total += everyCut(c, () -> c.client.generate(1), () -> {
                int made = c.client.identify().leavesMade;
                check(made == want - 1 || made == want, "a cut leaves the leaf made or not");
            });
            check(c.client.identify().leavesMade == want, "leaf " + leaf + " made");
        }
        while (c.client.generate(16) < 1024) {
            // the rest without cuts
        }
        byte[] cert = testCertificate(c);
        refused(0x6700, () -> c.client.writeCert(0, Arrays.copyOf(cert, 513)), "a certificate part over 512 bytes");
        for (int at = 0; at < cert.length; at += 512) {
            final int from = at;
            byte[] part = Arrays.copyOfRange(cert, from, Math.min(cert.length, from + 512));
            total += everyCut(c, () -> c.client.writeCert(from, part), () -> {
                check(c.client.identify().phase == GhostCard.PHASE_LOADING, "still loading");
            });
        }
        total += everyCut(c, () -> c.client.finish(cert.length), () -> {
            Identity id = c.client.identify();
            check(id.phase == GhostCard.PHASE_LOADING && id.certLen == 0 || id.phase == GhostCard.PHASE_READY,
                    "loading or ready");
        });
        check(c.client.identify().phase == GhostCard.PHASE_READY, "ready");
        same(c.client.certificate(), cert, "the certificate");
        // Leaves made across cuts sign correctly: the first eight Checks use them.
        byte[] pub = c.client.publicKey();
        for (int i = 0; i < 8; i++) {
            check(verifiedCheck(c, pub).leaf == i, "leaf " + i + " signs");
        }
        System.out.printf("      loading: %d cut points%n", total);
    }
}
