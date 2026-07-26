// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.*;
import org.globalplatform.GPSystem;
import org.globalplatform.Personalization;

// Records what the runtime does with CLEAR_ON_DESELECT memory, with the currently selected applet,
// and with the OPEN services an applet reaches before it has registered, from the applet's own point
// of view. Probes run at two moments: inside install(), and inside processData() while a Security
// Domain forwards STORE DATA. Every outcome goes into a persistent results array read back over
// INS_READ; INS_TOUCH repeats the same operations with this applet selected and answers inline.
// Slot 0 carries a step marker written before each probe is attempted, so a probe that kills the
// applet outright instead of throwing something catchable is still visible afterwards.
// Outcome byte: 0x00 ok, 0x01 java.lang.SecurityException, 0x02 SystemException with its reason in
// the two following bytes, 0x03 any other exception, 0xFF the probe never ran.
public class ContextProbeApplet extends Applet implements Personalization {

    public static final byte INS_READ  = (byte) 0x10;
    public static final byte INS_TOUCH = (byte) 0x11;

    private static final short COD_LEN = 8;
    private static final short RESULTS_LEN = 80;

    private static final byte MARK = (byte) 0x5A;

    private static final byte OUT_OK       = (byte) 0x00;
    private static final byte OUT_SECURITY = (byte) 0x01;
    private static final byte OUT_SYSTEM   = (byte) 0x02;
    private static final byte OUT_OTHER    = (byte) 0x03;
    private static final byte NOT_RUN      = (byte) 0xFF;

    // Whether a service handed back an object or null.
    private static final byte ABSENT  = (byte) 0x00;
    private static final byte PRESENT = (byte) 0x01;

    private static final byte STEP_CTOR_GP     = (byte) 0x10;
    private static final byte STEP_CTOR_COD    = (byte) 0x11;
    private static final byte STEP_INSTALL_AID = (byte) 0x12;
    private static final byte STEP_INSTALL_COD = (byte) 0x13;
    private static final byte STEP_PERSO_READ  = (byte) 0x21;
    private static final byte STEP_PERSO_WRITE = (byte) 0x22;
    private static final byte STEP_PERSO_COPY  = (byte) 0x23;
    private static final byte STEP_PERSO_MAKE  = (byte) 0x24;
    private static final byte STEP_PERSO_AIDS  = (byte) 0x25;
    private static final byte STEP_PERSO_DONE  = (byte) 0x2F;

    private static final short SLOT_STEP        = 0;
    private static final short SLOT_CTOR_COD    = 1;
    private static final short SLOT_COD_REAL    = 4;
    private static final short SLOT_INSTALL_AID = 5;
    private static final short SLOT_INSTALL_COD = 6;
    private static final short SLOT_PERSO_READ  = 9;
    private static final short SLOT_PERSO_WRITE = 12;
    private static final short SLOT_PERSO_COPY  = 15;
    private static final short SLOT_PERSO_MAKE  = 18;
    private static final short SLOT_PERSO_AID   = 21;
    private static final short SLOT_PERSO_PREV  = 38;
    private static final short SLOT_INSTALL_AID_BYTES = 55;
    private static final short SLOT_PRE_GP       = 72;
    private static final short SLOT_PRE_ENTRY    = 75;
    private static final short SLOT_PRE_CVM      = 76;
    private static final short SLOT_PRE_SC       = 77;
    private static final short SLOT_PRE_STATE    = 78;
    private static final short SLOT_POST_ENTRY   = 79;

    private final byte[] results;
    // Destination of the copy probe and sink for the read probe, so neither can be optimized away.
    private final byte[] scratch;
    private byte[] cod;

    private ContextProbeApplet() {
        results = new byte[RESULTS_LEN];
        Util.arrayFillNonAtomic(results, (short) 0, RESULTS_LEN, NOT_RUN);
        scratch = new byte[COD_LEN];
        results[SLOT_COD_REAL] = 0;
        // What the OPEN answers an applet that has not called register() yet.
        results[SLOT_STEP] = STEP_CTOR_GP;
        try {
            results[SLOT_PRE_ENTRY] = present(GPSystem.getRegistryEntry(null));
            results[SLOT_PRE_CVM] = present(GPSystem.getCVM(GPSystem.CVM_GLOBAL_PIN));
            results[SLOT_PRE_SC] = present(GPSystem.getSecureChannel());
            results[SLOT_PRE_STATE] = GPSystem.getCardContentState();
            ok(results, SLOT_PRE_GP);
        } catch (Throwable t) {
            fail(results, SLOT_PRE_GP, t);
        }
        results[SLOT_STEP] = STEP_CTOR_COD;
        try {
            cod = JCSystem.makeTransientByteArray(COD_LEN, JCSystem.CLEAR_ON_DESELECT);
            results[SLOT_COD_REAL] = 1;
            ok(results, SLOT_CTOR_COD);
        } catch (Throwable t) {
            fail(results, SLOT_CTOR_COD, t);
        }
        // Persistent stand-in keeps the later probes runnable on a runtime that refuses the allocation.
        if (cod == null) {
            cod = new byte[COD_LEN];
        }
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        ContextProbeApplet applet = new ContextProbeApplet();
        applet.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        applet.afterRegister(bArray, bOffset);
    }

    // Install-time probes, run once the instance is registered.
    private void afterRegister(byte[] bArray, short bOffset) {
        results[SLOT_POST_ENTRY] = present(GPSystem.getRegistryEntry(null));
        results[SLOT_STEP] = STEP_INSTALL_AID;
        AID my = JCSystem.getAID();
        captureAID(my, SLOT_INSTALL_AID_BYTES);
        if (my == null) {
            results[SLOT_INSTALL_AID] = 0;
        } else if (my.equals(bArray, (short) (bOffset + 1), bArray[bOffset])) {
            results[SLOT_INSTALL_AID] = 1;
        } else {
            results[SLOT_INSTALL_AID] = 2;
        }
        results[SLOT_STEP] = STEP_INSTALL_COD;
        try {
            byte[] extra = JCSystem.makeTransientByteArray(COD_LEN, JCSystem.CLEAR_ON_DESELECT);
            extra[0] = MARK;
            ok(results, SLOT_INSTALL_COD);
        } catch (Throwable t) {
            fail(results, SLOT_INSTALL_COD, t);
        }
    }

    public short processData(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        results[SLOT_STEP] = STEP_PERSO_READ;
        try {
            scratch[0] = cod[0];
            ok(results, SLOT_PERSO_READ);
        } catch (Throwable t) {
            fail(results, SLOT_PERSO_READ, t);
        }
        results[SLOT_STEP] = STEP_PERSO_WRITE;
        try {
            cod[0] = MARK;
            ok(results, SLOT_PERSO_WRITE);
        } catch (Throwable t) {
            fail(results, SLOT_PERSO_WRITE, t);
        }
        results[SLOT_STEP] = STEP_PERSO_COPY;
        try {
            // COD_LEN, not cod.length: arraylength is itself checked (JCRE 3.2 6.2.8.2) and would
            // settle the probe before arrayCopyNonAtomic ever sees the array.
            Util.arrayCopyNonAtomic(cod, (short) 0, scratch, (short) 0, COD_LEN);
            ok(results, SLOT_PERSO_COPY);
        } catch (Throwable t) {
            fail(results, SLOT_PERSO_COPY, t);
        }
        results[SLOT_STEP] = STEP_PERSO_MAKE;
        try {
            byte[] extra = JCSystem.makeTransientByteArray(COD_LEN, JCSystem.CLEAR_ON_DESELECT);
            extra[0] = MARK;
            ok(results, SLOT_PERSO_MAKE);
        } catch (Throwable t) {
            fail(results, SLOT_PERSO_MAKE, t);
        }
        results[SLOT_STEP] = STEP_PERSO_AIDS;
        captureAID(JCSystem.getAID(), SLOT_PERSO_AID);
        captureAID(JCSystem.getPreviousContextAID(), SLOT_PERSO_PREV);
        results[SLOT_STEP] = STEP_PERSO_DONE;
        return 0;
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case INS_READ:
                Util.arrayCopyNonAtomic(results, (short) 0, buffer, (short) 0, RESULTS_LEN);
                apdu.setOutgoingAndSend((short) 0, RESULTS_LEN);
                return;
            case INS_TOUCH:
                touch(buffer);
                apdu.setOutgoingAndSend((short) 0, (short) 3);
                return;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    // The same operations with this applet selected. The outcome goes straight into the response,
    // leaving the recorded results untouched, so the read-back order does not matter.
    private void touch(byte[] buffer) {
        try {
            cod[0] = MARK;
            scratch[0] = cod[0];
            Util.arrayCopyNonAtomic(cod, (short) 0, scratch, (short) 0, COD_LEN);
            byte[] extra = JCSystem.makeTransientByteArray(COD_LEN, JCSystem.CLEAR_ON_DESELECT);
            extra[0] = MARK;
            ok(buffer, (short) 0);
        } catch (Throwable t) {
            fail(buffer, (short) 0, t);
        }
    }

    // Length-prefixed AID at the given slot; length 0 marks a null AID.
    private void captureAID(AID aid, short slot) {
        if (aid == null) {
            results[slot] = 0;
            return;
        }
        results[slot] = (byte) aid.getBytes(results, (short) (slot + 1));
    }

    private static byte present(Object o) {
        return o == null ? ABSENT : PRESENT;
    }

    private static void ok(byte[] dst, short off) {
        dst[off] = OUT_OK;
        Util.setShort(dst, (short) (off + 1), (short) 0);
    }

    private static void fail(byte[] dst, short off, Throwable t) {
        byte outcome = OUT_OTHER;
        short reason = 0;
        if (t instanceof SecurityException) {
            outcome = OUT_SECURITY;
        } else if (t instanceof SystemException) {
            outcome = OUT_SYSTEM;
            reason = ((SystemException) t).getReason();
        }
        dst[off] = outcome;
        Util.setShort(dst, (short) (off + 1), reason);
    }
}
