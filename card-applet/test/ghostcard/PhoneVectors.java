package ghostcard;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import ghostcard.host.Ghost;
import ghostcard.host.Ghost.Statement;

/**
 * The phone's test vectors (test/phone-vectors.txt): one card's real answers
 * on jcardsim, for the wallet's own checks of a card (core/src/java_card.rs)
 * to be tested against. A blank Check, a Make from the first case of
 * vectors.txt, a Check confirming the right open code, one with a wrong code,
 * an Open and a Check of the opened card, each with its LMS signature.
 *
 * The answers carry fresh LMS randomness, so the file is written once (with
 * UPDATE_PHONE_VECTORS=1) and kept; every run checks that every signature in
 * it still verifies with Bouncy Castle's RFC 8554 verifier and that its
 * statements say what the file says they do.
 */
final class PhoneVectors {

    static final HexFormat HEX = HexFormat.of();

    private PhoneVectors() {
    }

    static byte[] counting(int start, int n) {
        byte[] b = new byte[n];
        for (int i = 0; i < n; i++) {
            b[i] = (byte) (start + i);
        }
        return b;
    }

    static Map<String, byte[]> record(Map<String, byte[]> v) {
        SimCard c = CardTests.loadedCard(1024);
        Map<String, byte[]> out = new LinkedHashMap<>();
        out.put("lms_public_key", c.client.publicKey());
        out.put("card_id", c.client.identify().cardId);

        byte[] code = counting(0x60, 20);
        byte[] wrongCode = counting(0x61, 20);
        byte[] codeHash = Ghost.codeHash(code);
        out.put("open_code", code);
        out.put("wrong_open_code", wrongCode);

        byte[] ch = counting(0x80, 32);
        byte[][] blank = c.client.check(ch, null);
        out.put("blank_challenge", ch);
        out.put("blank_statement", blank[0]);
        out.put("blank_signature", blank[1]);

        c.random.push(v.get("card_random"));
        c.random.push(v.get("salt"));
        c.random.push(v.get("note_random"));
        out.put("amount", v.get("amount"));
        out.put("chain_id", v.get("chain_id"));
        out.put("writer_nonce", v.get("writer_nonce"));
        out.put("card_random", v.get("card_random"));
        out.put("make_answer", c.client.make(v.get("amount"), v.get("chain_id"), v.get("writer_nonce"), codeHash));

        ch = counting(0xa0, 32);
        byte[] confirm = Ghost.confirmation(codeHash, ch);
        byte[][] sealed = c.client.check(ch, confirm);
        out.put("sealed_challenge", ch);
        out.put("sealed_confirmation", confirm);
        out.put("sealed_statement", sealed[0]);
        out.put("sealed_signature", sealed[1]);

        ch = counting(0xc0, 32);
        confirm = Ghost.confirmation(Ghost.codeHash(wrongCode), ch);
        byte[][] wrong = c.client.check(ch, confirm);
        out.put("wrong_code_challenge", ch);
        out.put("wrong_code_confirmation", confirm);
        out.put("wrong_code_statement", wrong[0]);
        out.put("wrong_code_signature", wrong[1]);

        ch = counting(0xe0, 32);
        out.put("open_challenge", ch);
        out.put("open_answer", c.client.open(code, ch));

        ch = counting(0x10, 32);
        byte[][] opened = c.client.check(ch, null);
        out.put("opened_challenge", ch);
        out.put("opened_statement", opened[0]);
        out.put("opened_signature", opened[1]);
        return out;
    }

    static void write(Path path, Map<String, byte[]> values) throws Exception {
        StringBuilder s = new StringBuilder();
        s.append("# One Ghost card's real answers on jcardsim, for the wallet's checks of a card\n");
        s.append("# (core/src/java_card.rs). Written by card-applet/test/ghostcard/PhoneVectors.java\n");
        s.append("# with UPDATE_PHONE_VECTORS=1; the applet tests check every signature still verifies.\n\n");
        for (Map.Entry<String, byte[]> e : values.entrySet()) {
            s.append(e.getKey()).append(" = ").append(HEX.formatHex(e.getValue())).append('\n');
        }
        Files.writeString(path, s.toString());
    }

    static Map<String, byte[]> read(Path path) throws Exception {
        Map<String, byte[]> m = new LinkedHashMap<>();
        for (String line : Files.readAllLines(path)) {
            line = line.strip();
            if (line.isEmpty() || line.startsWith("#")) {
                continue;
            }
            String[] kv = line.split("=", 2);
            m.put(kv[0].strip(), HEX.parseHex(kv[1].strip()));
        }
        return m;
    }

    /** Writes the file when asked, then checks it. */
    static void run(Path path, List<Map<String, byte[]>> cases) throws Exception {
        if (System.getenv("UPDATE_PHONE_VECTORS") != null) {
            write(path, record(cases.get(0)));
        }
        Map<String, byte[]> v = read(path);
        byte[] pub = v.get("lms_public_key");
        byte[] cardId = v.get("card_id");
        String[][] checks = {
            {"blank", "0", "0"},
            {"sealed", "1", "1"},
            {"wrong_code", "1", "2"},
            {"opened", "2", "0"},
        };
        long leaf = 0;
        for (String[] k : checks) {
            byte[] st = v.get(k[0] + "_statement");
            CardTests.check(Ghost.lmsVerify(pub, st, v.get(k[0] + "_signature")), k[0] + ": signature verifies");
            Statement s = new Statement(st);
            CardTests.same(s.cardId, cardId, k[0] + ": card id");
            CardTests.same(s.challenge, v.get(k[0] + "_challenge"), k[0] + ": challenge");
            CardTests.check(s.state == Integer.parseInt(k[1]), k[0] + ": state");
            CardTests.check(s.confirmation == Integer.parseInt(k[2]), k[0] + ": code confirmation");
            CardTests.check(s.leaf == leaf, k[0] + ": leaf " + leaf);
            leaf++;
            byte[] other = st.clone();
            other[40] ^= 1;
            CardTests.check(!Ghost.lmsVerify(pub, other, v.get(k[0] + "_signature")), k[0] + ": only its statement");
        }
        byte[] make = v.get("make_answer");
        Statement sealed = new Statement(v.get("sealed_statement"));
        CardTests.check(Ghost.u32pub(make, 0) == 1 && sealed.fill == 1, "the first fill");
        CardTests.same(Arrays.copyOfRange(make, 4, 36), sealed.commitment, "Make's commitment is the statement's");
        CardTests.same(Ghost.sha256(Arrays.copyOfRange(make, 36, 466)), sealed.digest, "digest of Make's commit data");
        byte[] release = Ghost.openRelease(cardId, v.get("open_code"), v.get("open_challenge"), 1, v.get("open_answer"));
        CardTests.same(Arrays.copyOf(release, 32), v.get("card_random"), "Open releases the card random");
        CardTests.same(Arrays.copyOfRange(release, 32, 64), v.get("writer_nonce"), "and the writer nonce");
    }
}
