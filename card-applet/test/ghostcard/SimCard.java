package ghostcard;

import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.security.SecureRandom;
import java.util.ArrayDeque;

import javacard.framework.AID;
import javacard.security.RandomData;

import com.licel.jcardsim.base.Simulator;
import com.licel.jcardsim.smartcardio.CardSimulator;

import ghostcard.host.CardClient;

/**
 * One applet on jcardsim, with the hooks the tests need: a power cut (see
 * test/tear/ghostcard/Nvm.java), a scripted random source, and a look at the
 * applet's private seed so the tests can check no answer ever carries it.
 */
final class SimCard {

    /** A random source that gives queued bytes first, then fresh random bytes. */
    static final class ScriptedRandom extends RandomData {
        final ArrayDeque<Byte> queue = new ArrayDeque<>();
        private final SecureRandom fallback = new SecureRandom();

        void push(byte[] bytes) {
            for (byte b : bytes) {
                queue.add(b);
            }
        }

        private void fillFrom(byte[] buf, short off, short len) {
            for (int i = 0; i < len; i++) {
                Byte b = queue.poll();
                buf[off + i] = b != null ? b : (byte) fallback.nextInt();
            }
        }

        @Override
        @SuppressWarnings("deprecation")
        public void generateData(byte[] buf, short off, short len) {
            fillFrom(buf, off, len);
        }

        @Override
        public short nextBytes(byte[] buf, short off, short len) {
            fillFrom(buf, off, len);
            return (short) (off + len);
        }

        @Override
        public void setSeed(byte[] buf, short off, short len) {
        }

        @Override
        public byte getAlgorithm() {
            return ALG_TRNG;
        }
    }

    static final AID AID_GHOST = new AID(CardClient.AID, (short) 0, (byte) CardClient.AID.length);

    final CardSimulator sim = new CardSimulator();
    final GhostCard applet;
    final ScriptedRandom random = new ScriptedRandom();
    final CardClient client;
    /** Every answer the card has given, for the secrecy test. */
    final java.io.ByteArrayOutputStream answers = new java.io.ByteArrayOutputStream();

    SimCard(int maxAnswer, byte[] installParams) {
        Nvm.arm(0);
        Nvm.powerOff();
        Nvm.installed = false;
        // jcardsim hands this array to install() as it is, so build what a
        // card manager gives: instance AID, control info, applet parameters.
        byte[] params = installParams == null ? new byte[0] : installParams;
        byte[] b = CardClient.concat(new byte[] {(byte) CardClient.AID.length}, CardClient.AID,
                new byte[] {0, (byte) params.length}, params);
        sim.installApplet(AID_GHOST, GhostCard.class, b, (short) 0, (byte) b.length);
        applet = lookup();
        Nvm.installed = true;
        try {
            Field f = GhostCard.class.getDeclaredField("rng");
            f.setAccessible(true);
            f.set(applet, random);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
        client = new CardClient(this::transmit, maxAnswer);
        sim.selectApplet(AID_GHOST);
    }

    private GhostCard lookup() {
        try {
            Field rt = Simulator.class.getDeclaredField("runtime");
            rt.setAccessible(true);
            Object runtime = rt.get(sim);
            Method get = runtime.getClass().getDeclaredMethod("getApplet", AID.class);
            get.setAccessible(true);
            return (GhostCard) get.invoke(runtime, AID_GHOST);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    byte[] transmit(byte[] command) {
        byte[] r;
        try {
            r = sim.transmitCommand(command);
        } catch (Nvm.Tear t) {
            r = new byte[] {0x6F, 0x00};
        }
        if (Nvm.torn) {
            r = new byte[] {0x6F, 0x00};
        }
        answers.writeBytes(r);
        return r;
    }

    /** Cuts the power: the open transaction (if any) is gone, RAM is cleared, the applet is selected again. */
    void powerCut() {
        Nvm.powerOff();
        Nvm.arm(0);
        sim.reset();
        sim.selectApplet(AID_GHOST);
    }

    byte[] field(String name) {
        try {
            Field f = GhostCard.class.getDeclaredField(name);
            f.setAccessible(true);
            return ((byte[]) f.get(applet)).clone();
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }
}
