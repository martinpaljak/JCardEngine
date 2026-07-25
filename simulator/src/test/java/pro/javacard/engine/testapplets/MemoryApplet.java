// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.engine.testapplets;

import javacard.framework.*;

public class MemoryApplet extends Applet {

    private static final byte INS_MEMORY  = (byte) 0x42;
    private static final byte INS_GLOBALS = (byte) 0x43;
    private static final byte P1_QUERY    = (byte) 0x00;
    private static final byte P1_GC       = (byte) 0x01;
    private static final byte P2_EXTENDED = (byte) 0x00;
    private static final byte P2_LEGACY   = (byte) 0x01;

    private final short[] scratch;

    // isTransient() and length of the install() bArray; both can only be queried while install() runs
    private final byte installBuffer;
    private final short installBufferLength;

    private MemoryApplet(byte[] bArray) {
        scratch = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);
        installBuffer = JCSystem.isTransient(bArray);
        installBufferLength = (short) bArray.length;
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MemoryApplet(bArray).register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_INS] == INS_GLOBALS) {
            doGlobals(apdu, buffer);
            return;
        }
        if (buffer[ISO7816.OFFSET_INS] != INS_MEMORY) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        switch (buffer[ISO7816.OFFSET_P1]) {
            case P1_QUERY:
                doQuery(apdu, buffer, buffer[ISO7816.OFFSET_P2]);
                break;
            case P1_GC:
                doGc();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
    }

    // Reports the memory type and length of the APDU buffer and the install() bArray recorded at construction.
    private void doGlobals(APDU apdu, byte[] buffer) {
        buffer[0] = JCSystem.isTransient(buffer);
        buffer[1] = installBuffer;
        Util.setShort(buffer, (short) 2, (short) buffer.length);
        Util.setShort(buffer, (short) 4, installBufferLength);
        apdu.setOutgoingAndSend((short) 0, (short) 6);
    }

    private void doQuery(APDU apdu, byte[] buffer, byte p2) {
        short len;
        if (p2 == P2_EXTENDED) {
            writeExtended(buffer, (short) 0, JCSystem.MEMORY_TYPE_PERSISTENT);
            writeExtended(buffer, (short) 4, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
            writeExtended(buffer, (short) 8, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
            len = (short) 12;
        } else if (p2 == P2_LEGACY) {
            Util.setShort(buffer, (short) 0, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
            Util.setShort(buffer, (short) 2, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
            Util.setShort(buffer, (short) 4, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
            len = (short) 6;
        } else {
            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
            return;
        }
        apdu.setOutgoingAndSend((short) 0, len);
    }

    private void writeExtended(byte[] buffer, short off, byte memoryType) {
        JCSystem.getAvailableMemory(scratch, (short) 0, memoryType);
        Util.setShort(buffer, off, scratch[0]);
        Util.setShort(buffer, (short) (off + 2), scratch[1]);
    }

    private void doGc() {
        if (!JCSystem.isObjectDeletionSupported()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        try {
            JCSystem.requestObjectDeletion();
        } catch (SystemException e) {
            ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
        }
    }
}
