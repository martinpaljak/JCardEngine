// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.*;

public class MemoryTestApplet extends Applet {

    private boolean[] booleanArray;
    private short[] shortArray;
    private Object[] objectArray;

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new MemoryTestApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case (byte) 0x01: // Allocate boolean array
                booleanArray = new boolean[10];
                SensitiveArrays.assertIntegrity(booleanArray);
                break;
            case (byte) 0x02: // Allocate short array
                shortArray = new short[5];
                SensitiveArrays.assertIntegrity(shortArray);
                break;
            case (byte) 0x03: // Allocate object array
                objectArray = new Object[3];
                SensitiveArrays.assertIntegrity(objectArray);
                break;
            case (byte) 0x04: // Clear arrays
                if (booleanArray != null) {
                    SensitiveArrays.clearArray(booleanArray);
                }
                if (shortArray != null) {
                    SensitiveArrays.clearArray(shortArray);
                }
                if (objectArray != null) {
                    SensitiveArrays.clearArray(objectArray);
                }
                break;
            case (byte) 0x05: // makeIntegritySensitiveArray transient
                Object transObj = SensitiveArrays.makeIntegritySensitiveArray(JCSystem.ARRAY_TYPE_BYTE, JCSystem.MEMORY_TYPE_TRANSIENT_RESET, (short) 10);
                if (!(transObj instanceof byte[])) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                if (JCSystem.isTransient(transObj) == JCSystem.MEMORY_TYPE_PERSISTENT) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                SensitiveArrays.assertIntegrity(transObj);
                break;
            case (byte) 0x06: // makeIntegritySensitiveArray persistent
                Object persObj = SensitiveArrays.makeIntegritySensitiveArray(JCSystem.ARRAY_TYPE_BYTE, JCSystem.MEMORY_TYPE_PERSISTENT, (short) 10);
                if (!(persObj instanceof byte[])) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                if (JCSystem.isTransient(persObj) != JCSystem.MEMORY_TYPE_PERSISTENT) {
                    ISOException.throwIt(ISO7816.SW_DATA_INVALID);
                }
                SensitiveArrays.assertIntegrity(persObj);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
