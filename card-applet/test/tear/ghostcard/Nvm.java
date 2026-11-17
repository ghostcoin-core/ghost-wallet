package ghostcard;

import java.util.ArrayList;
import java.util.List;

/**
 * The tests' stand-in for src/ghostcard/Nvm.java: the same writes, plus a
 * power cut that can be armed at any one of them.
 *
 * Each write, and each commit, is one numbered point. When the armed point is
 * reached the card loses power there: an open transaction is rolled back,
 * and {@link Tear} is thrown so the command never finishes. This
 * is what a Java Card guarantees on a real tear, and the tests check that
 * every command leaves the card before or after itself, never between.
 *
 * It also checks the applet's discipline: every write after install is
 * inside a transaction, and transactions never nest.
 */
final class Nvm {

    /** Thrown where the power is cut. */
    static final class Tear extends RuntimeException {
        Tear() {
            super("power cut");
        }
    }

    private static final class Saved {
        final byte[] array;
        final short off;
        final byte[] old;

        Saved(byte[] array, short off, short len) {
            this.array = array;
            this.off = off;
            this.old = new byte[len];
            System.arraycopy(array, off, old, 0, len);
        }
    }

    /** Points counted since the last reset(). */
    static int points;
    /** The point to cut the power at, or 0 for none. */
    static int tearAt;
    /** Whether the power was cut. */
    static boolean torn;

    private static boolean inTransaction;
    /** Set once the applet is installed: from then on every write must be in a transaction. */
    static boolean installed;
    private static final List<Saved> journal = new ArrayList<>();

    private Nvm() {
    }

    /** Clears the counters; arms a cut at point `at` (0: none). */
    static void arm(int at) {
        points = 0;
        tearAt = at;
        torn = false;
    }

    /** Called after a cut: the card has no open transaction any more. */
    static void powerOff() {
        inTransaction = false;
        journal.clear();
    }

    /** Counts a point; returns true when the power is cut here. */
    private static boolean point() {
        points++;
        return tearAt != 0 && points == tearAt;
    }

    private static void cut() {
        if (inTransaction) {
            for (int i = journal.size() - 1; i >= 0; i--) {
                Saved s = journal.get(i);
                System.arraycopy(s.old, 0, s.array, s.off, s.old.length);
            }
        }
        inTransaction = false;
        journal.clear();
        torn = true;
        throw new Tear();
    }

    static void begin() {
        if (inTransaction) {
            throw new IllegalStateException("nested transaction");
        }
        inTransaction = true;
        journal.clear();
    }

    static void commit() {
        if (!inTransaction) {
            throw new IllegalStateException("commit without a transaction");
        }
        if (point()) {
            cut();
        }
        inTransaction = false;
        journal.clear();
    }

    private static void atomic(byte[] dst, short off, short len, byte[] src, short srcOff, boolean fill, byte value) {
        if (point()) {
            cut();
        }
        if (inTransaction) {
            journal.add(new Saved(dst, off, len));
        } else if (installed) {
            throw new IllegalStateException("a persistent write outside a transaction");
        }
        if (fill) {
            java.util.Arrays.fill(dst, off, off + len, value);
        } else {
            System.arraycopy(src, srcOff, dst, off, len);
        }
    }

    static void setByte(byte[] dst, short off, byte value) {
        atomic(dst, off, (short) 1, null, (short) 0, true, value);
    }

    static void copy(byte[] src, short srcOff, byte[] dst, short dstOff, short len) {
        atomic(dst, dstOff, len, src, srcOff, false, (byte) 0);
    }

}
