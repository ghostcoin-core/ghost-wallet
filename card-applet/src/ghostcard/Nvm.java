package ghostcard;

import javacard.framework.JCSystem;
import javacard.framework.Util;

/**
 * Every write the applet makes to persistent memory goes through this class,
 * so the tests can cut the power at each one (test/tear/ghostcard/Nvm.java
 * replaces this class there). The applet never writes a persistent array or
 * field any other way after install.
 *
 * Every write after install happens between begin() and commit(), so a
 * command that loses power leaves the card as it was before it.
 */
final class Nvm {

    private Nvm() {
    }

    static void begin() {
        JCSystem.beginTransaction();
    }

    static void commit() {
        JCSystem.commitTransaction();
    }

    /** One byte; journaled inside a transaction. */
    static void setByte(byte[] dst, short off, byte value) {
        dst[off] = value;
    }

    /** An atomic copy; journaled inside a transaction. */
    static void copy(byte[] src, short srcOff, byte[] dst, short dstOff, short len) {
        Util.arrayCopy(src, srcOff, dst, dstOff, len);
    }
}
