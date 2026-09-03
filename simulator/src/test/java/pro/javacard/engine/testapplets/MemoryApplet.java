// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: MIT
package pro.javacard.engine.testapplets;

import javacard.framework.*;

public class MemoryApplet extends Applet {

    private static final byte INS_MEMORY  = (byte) 0x42;
    private static final boolean DEBUG = false;
    private static final byte INS_GLOBALS = (byte) 0x43;
    private static final byte P1_QUERY    = (byte) 0x00;
    private static final byte P1_GC       = (byte) 0x01;
    private static final byte P2_EXTENDED = (byte) 0x00;
    private static final byte P2_LEGACY   = (byte) 0x01;

    // Available memory readings in one of the two JCSystem formats, plus the GC request that frees some
    interface Report {
        // Writes the readings to dst at offset and returns their length
        short extract(byte[] dst, short offset);

        void gc();
    }

    // 32-bit readings via getAvailableMemory(short[], short, byte), four bytes per memory type
    static final class Extended implements Report {
        private final short[] scratch = JCSystem.makeTransientShortArray((short) 2, JCSystem.CLEAR_ON_RESET);

        public short extract(byte[] dst, short offset) {
            write(dst, offset, JCSystem.MEMORY_TYPE_PERSISTENT);
            write(dst, (short) (offset + 4), JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
            write(dst, (short) (offset + 8), JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
            return 12;
        }

        private void write(byte[] dst, short off, byte memoryType) {
            // Two shorts per reading
            JCSystem.getAvailableMemory(scratch, (short) 0, memoryType);
            Util.setShort(dst, off, scratch[0]);
            Util.setShort(dst, (short) (off + 2), scratch[1]);
        }

        public void gc() {
            // step: Refuse when the runtime cannot delete objects
            if (!JCSystem.isObjectDeletionSupported()) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            JCSystem.requestObjectDeletion();
        }
    }

    // 16-bit readings via getAvailableMemory(byte), saturated at 32767
    static final class Legacy implements Report {
        private static final byte[] TYPES = {JCSystem.MEMORY_TYPE_PERSISTENT, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT};

        public short extract(byte[] dst, short offset) {
            short i = 0;
            // step: Three readings
            while (i < TYPES.length) {
                // step: One reading
                Util.setShort(dst, (short) (offset + 2 * i), JCSystem.getAvailableMemory(TYPES[i]));
                i++;
            }
            return 6;
        }

        public void gc() {
            // step: A refused request surfaces as SystemException
            try {
                JCSystem.requestObjectDeletion();
            } catch (SystemException e) {
                ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
            }
        }
    }

    private final Report extended = new Extended();
    private final Report legacy = new Legacy();

    // isTransient() and length of the install() bArray; both can only be queried while install() runs
    private final byte installBuffer;
    private final short installBufferLength;

    private MemoryApplet(byte[] bArray) {
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

        if (DEBUG) {
            // step: Never compiled
            ISOException.throwIt(ISO7816.SW_UNKNOWN);
        }
        // step: Dispatch on INS
        byte[] buffer = apdu.getBuffer();
        if (buffer[ISO7816.OFFSET_INS] == INS_GLOBALS) {
            doGlobals(apdu, buffer);
            return;
        }
        if (buffer[ISO7816.OFFSET_INS] != INS_MEMORY) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        // step: P2 picks the report format
        Report report = report(buffer[ISO7816.OFFSET_P2]);
        switch (buffer[ISO7816.OFFSET_P1]) {
            case P1_QUERY:
                apdu.setOutgoingAndSend((short) 0, report.extract(buffer, (short) 0));
                break;
            case P1_GC:
                report.gc();
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        }
        // step: Done
    }

    private Report report(byte p2) {
        if (p2 == P2_EXTENDED) {
            return extended;
        }
        if (p2 == P2_LEGACY) {
            return legacy;
        }
        ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
        return null;
    }

    // Reports the memory type and length of the APDU buffer and the install() bArray recorded at construction.
    private void doGlobals(APDU apdu, byte[] buffer) {
        buffer[0] = JCSystem.isTransient(buffer);
        buffer[1] = installBuffer;
        Util.setShort(buffer, (short) 2, (short) buffer.length);
        Util.setShort(buffer, (short) 4, installBufferLength);
        apdu.setOutgoingAndSend((short) 0, (short) 6);
    }
}
