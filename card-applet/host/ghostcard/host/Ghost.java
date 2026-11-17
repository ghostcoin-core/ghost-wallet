package ghostcard.host;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.digests.KeccakDigest;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.LMSPublicKeyParameters;
import org.bouncycastle.crypto.signers.LMSSigner;

/**
 * What a phone does with the card's answers, written independently of the
 * applet: Ghost's derivations for a card's coin (checked against vectors from
 * Ghost's own client), the seal statement and its LMS signature, and Open's
 * AES-256-CTR plus AES-CMAC release.
 */
public final class Ghost {

    private Ghost() {
    }

    // ---------------- hashes ----------------

    public static byte[] sha3(byte[]... parts) {
        try {
            MessageDigest d = MessageDigest.getInstance("SHA3-256");
            for (byte[] p : parts) {
                d.update(p);
            }
            return d.digest();
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    public static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }

    static byte[] keccak(byte[]... parts) {
        KeccakDigest d = new KeccakDigest(256);
        for (byte[] p : parts) {
            d.update(p, 0, p.length);
        }
        byte[] out = new byte[32];
        d.doFinal(out, 0);
        return out;
    }

    static byte[] tag(String t) {
        byte[] b = t.getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[b.length + 1];
        out[0] = (byte) b.length;
        System.arraycopy(b, 0, out, 1, b.length);
        return out;
    }

    static byte[] ascii(String s) {
        return s.getBytes(StandardCharsets.US_ASCII);
    }

    // ---------------- a card's coin, as Ghost's client computes it ----------------

    /** Everything Make computes, from its inputs. */
    public static final class Coin {
        public byte[] seed;
        public byte[] fingerprint;
        public byte[] commitment;
        public byte[] marker;
        public byte[] commitData;
        public byte[] digest;
    }

    /**
     * The coin a card makes from its random bytes and the writer's nonce: the
     * Phantom Key's seed bytes, then F, C, the marker and the commit data with
     * its note sealed under the key's note key (number 0, empty rule).
     */
    public static Coin coin(byte[] cardRandom, byte[] writerNonce, byte[] salt, byte[] noteRandom9,
                            byte[] amount12, byte[] chainId8) {
        Coin c = new Coin();
        c.seed = sha3(ascii("ghost-card-key"), cardRandom, writerNonce);
        byte[] key = CardClient.concat(new byte[] {0x20}, c.seed);
        byte[] s = sha3(tag("ghost/secret/v1"), key);
        byte[] r = sha3(tag("ghost/reveal-secret/v1"), key);
        byte[] b = sha3(tag("ghost/blinding/v1"), key, new byte[8]);
        byte[] noteKey = sha3(tag("ghost/note-key/v1"), key);
        byte[] lookup = sha3(tag("ghost/note-tag/v1"), noteKey, new byte[8]);
        byte[] coinV2 = {0x02, 0x01};
        c.fingerprint = keccak(tag("ghost/coin-fingerprint/v2"), s, r, b, salt, coinV2, new byte[32], new byte[32]);
        c.commitment = keccak(tag("ghost/coin-commitment/v1"), coinV2, c.fingerprint, new byte[20], amount12);
        c.marker = keccak(tag("ghost/coin-marker/v2"), r, b, salt);

        byte[] plain = new byte[352];
        plain[0] = 0x03;
        plain[1] = 0x01;
        plain[2] = 0x02;
        plain[3] = 0x01;
        System.arraycopy(amount12, 0, plain, 12, 12);
        System.arraycopy(salt, 0, plain, 96, 16);
        byte[] nonce = CardClient.concat(Arrays.copyOf(lookup, 3), noteRandom9);
        byte[] sealed;
        try {
            Cipher cc = Cipher.getInstance("ChaCha20-Poly1305");
            cc.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(noteKey, "ChaCha20"), new IvParameterSpec(nonce));
            cc.updateAAD(CardClient.concat(chainId8, c.commitment));
            sealed = cc.doFinal(plain);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        c.commitData = CardClient.concat(new byte[] {0x00, 0x03}, c.fingerprint, salt, nonce, sealed);
        c.digest = sha256(c.commitData);
        return c;
    }

    // ---------------- open codes ----------------

    public static byte[] codeHash(byte[] code) {
        return sha3(code);
    }

    /** The value a Check sends to confirm an open code for one challenge. */
    public static byte[] confirmation(byte[] codeHash, byte[] challenge) {
        return sha3(ascii("ghost-card-code"), codeHash, challenge);
    }

    // ---------------- the seal statement ----------------

    /** A parsed seal statement. */
    public static final class Statement {
        public final byte[] raw;
        public final byte[] cardId;
        public final int state;
        public final long fill;
        public final byte[] chainId;
        public final byte[] amount;
        public final byte[] commitment;
        public final byte[] digest;
        public final byte[] marker;
        public final int checksLeft;
        public final long leaf;
        public final int confirmation;
        public final byte[] challenge;

        public Statement(byte[] s) {
            if (s.length != CardClient.STATEMENT_LEN) {
                throw new IllegalArgumentException("statement length " + s.length);
            }
            if (!Arrays.equals(Arrays.copyOf(s, 18), ascii("ghost-card-seal-v1"))) {
                throw new IllegalArgumentException("not a seal statement");
            }
            raw = s;
            cardId = Arrays.copyOfRange(s, 18, 34);
            state = s[34];
            fill = u32(s, 35);
            chainId = Arrays.copyOfRange(s, 39, 47);
            amount = Arrays.copyOfRange(s, 47, 59);
            commitment = Arrays.copyOfRange(s, 59, 91);
            digest = Arrays.copyOfRange(s, 91, 123);
            marker = Arrays.copyOfRange(s, 123, 155);
            checksLeft = ((s[155] & 0xFF) << 8) | (s[156] & 0xFF);
            leaf = u32(s, 157);
            confirmation = s[161];
            challenge = Arrays.copyOfRange(s, 162, 194);
        }
    }

    public static long u32pub(byte[] b, int o) {
        return u32(b, o);
    }

    static long u32(byte[] b, int o) {
        return ((b[o] & 0xFFL) << 24) | ((b[o + 1] & 0xFF) << 16) | ((b[o + 2] & 0xFF) << 8) | (b[o + 3] & 0xFF);
    }

    /** Checks an RFC 8554 LMS signature with Bouncy Castle's verifier. */
    public static boolean lmsVerify(byte[] publicKey, byte[] message, byte[] signature) {
        try {
            LMSSigner v = new LMSSigner();
            v.init(false, LMSPublicKeyParameters.getInstance(publicKey));
            return v.verifySignature(message, signature);
        } catch (Exception e) {
            return false;
        }
    }

    // ---------------- Open ----------------

    /**
     * Checks an Open answer's tag and decrypts it: returns the card random
     * and the writer nonce (64 bytes), or throws when the tag is wrong.
     */
    public static byte[] openRelease(byte[] cardId, byte[] code, byte[] challenge, long expectFill, byte[] answer) {
        if (answer.length != 100) {
            throw new IllegalArgumentException("Open answer length " + answer.length);
        }
        byte[] fill = Arrays.copyOfRange(answer, 0, 4);
        if (u32(fill, 0) != expectFill) {
            throw new SecurityException("Open answer for another fill");
        }
        byte[] ctr = Arrays.copyOfRange(answer, 4, 20);
        byte[] ct = Arrays.copyOfRange(answer, 20, 84);
        byte[] tagGot = Arrays.copyOfRange(answer, 84, 100);
        byte[] encKey = sha3(ascii("ghost-card-open-enc"), cardId, fill, code, challenge);
        byte[] macKey = sha3(ascii("ghost-card-open-mac"), cardId, fill, code, challenge);
        CMac mac = new CMac(AESEngine.newInstance());
        mac.init(new KeyParameter(macKey));
        byte[] in = CardClient.concat(ascii("ghost-card-open-v1"), cardId, fill, challenge, ctr, ct);
        mac.update(in, 0, in.length);
        byte[] tag = new byte[16];
        mac.doFinal(tag, 0);
        if (!MessageDigest.isEqual(tag, tagGot)) {
            throw new SecurityException("Open answer's tag is wrong");
        }
        try {
            Cipher c = Cipher.getInstance("AES/CTR/NoPadding");
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(encKey, "AES"), new IvParameterSpec(ctr));
            return c.doFinal(ct);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
    }
}
