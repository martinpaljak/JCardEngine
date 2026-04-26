// SPDX-FileCopyrightText: 2025 Martin Paljak
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.*;
import org.globalplatform.GPSystem;
import org.globalplatform.SecureChannel;
import pro.javacard.engine.testapplets.testlib.TestLibrary;

public final class GlobalPlatformTestApplet extends Applet {
    public static final byte INS_INITIALIZE_UPDATE = 0x50; // GP
    public static final byte INS_EXTERNAL_AUTHENTICATE = ISO7816.INS_EXTERNAL_AUTHENTICATE;

    byte[] data = new byte[128];
    short value = 0;

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short) (bArray[offset] + 1); // instance AID
        offset += (short) (bArray[offset] + 1); // privileges - expect none
        GlobalPlatformTestApplet applet = new GlobalPlatformTestApplet(bArray, (short) (offset + 1), bArray[offset]);
        if (JCSystem.getAID() != null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        applet.register(bArray, (short) (bOffset + 1), bArray[bOffset]);
        if (JCSystem.getAID() == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        try {
            // Second register must throw
            applet.register();
        } catch (SystemException e) {
            if (e.getReason() != SystemException.ILLEGAL_AID) {
                throw e;
            }
        }
    }


    private GlobalPlatformTestApplet(byte[] parameters, short parametersOffset, byte parametersLength) {
        if (parametersLength > 0) {
            Util.arrayCopy(parameters, parametersOffset, data, (short) 1, parametersLength);
            data[0] = parametersLength;
        }
        value = TestLibrary.valueHelper();
    }

    @Override
    public void deselect() {
        GPSystem.getSecureChannel().resetSecurity();
    }

    @Override
    public boolean select() {
        // NOTE: these are redundant in real life, as OPEN would not allow to select such applet.
        // Here only for test coverage
        if (GPSystem.getCardState() != GPSystem.CARD_SECURED) {
            return false;
        }
        if (GPSystem.getCardContentState() != GPSystem.APPLICATION_SELECTABLE) {
            return false;
        }
        return true;
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();

        // Filter out GP commands to pass to SecureChannel. SecureChannel validates the CLA.
        if (buffer[ISO7816.OFFSET_INS] == INS_INITIALIZE_UPDATE || buffer[ISO7816.OFFSET_INS] == INS_EXTERNAL_AUTHENTICATE) {
            short offset = GPSystem.getSecureChannel().processSecurity(apdu);
            apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, offset);
        } else if (apdu.isSecureMessagingCLA() && ((buffer[ISO7816.OFFSET_CLA] & 0x80) == 0x80)) {
            // Custom CLA
            SecureChannel sec = GPSystem.getSecureChannel();
            // Require encryption
            if ((sec.getSecurityLevel() & (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION)) != (SecureChannel.AUTHENTICATED | SecureChannel.C_DECRYPTION)) {
                ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            }
            short inlen = apdu.setIncomingAndReceive();
            // Unwrap in place to APDU buffer, keeping the APDU header intact
            sec.unwrap(buffer, (short) 0, (short) (apdu.getOffsetCdata() + inlen));
            short len = (short) (buffer[ISO7816.OFFSET_LC] & 0xFF);

            switch (buffer[ISO7816.OFFSET_INS]) {
                case 0x42:
                    len = sec.decryptData(buffer, apdu.getOffsetCdata(), len);
                    len = unpad80(buffer, apdu.getOffsetCdata(), len);
                    if (len < 7 || len > 0x7f) {
                        ISOException.throwIt(ISO7816.SW_WRONG_DATA);
                    }

                    try {
                        JCSystem.abortTransaction();
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    } catch (TransactionException e) {
                        // Ignore
                    }
                    try {
                        JCSystem.commitTransaction();
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    } catch (TransactionException e) {
                        // Ignore
                    }
                    try {
                        JCSystem.beginTransaction();
                        try {
                            JCSystem.beginTransaction();
                            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                        } catch (TransactionException e) {
                            JCSystem.abortTransaction();
                        }
                        // Start a new transaction
                        JCSystem.beginTransaction();
                        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, data, (short) 1, len);
                        data[0] = (byte) len;
                    } finally {
                        if (JCSystem.getTransactionDepth() == 1) {
                            JCSystem.commitTransaction();
                        }
                    }
                    return;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        } else {
            switch (buffer[ISO7816.OFFSET_INS]) {
                case 0x42:
                    // Delete everything.
                    if (JCSystem.isObjectDeletionSupported()) {
                        JCSystem.requestObjectDeletion();
                    }
                    if (data[0] == 0) {
                        ISOException.throwIt(ISO7816.SW_COMMAND_NOT_ALLOWED);
                    }
                    if (GPSystem.getCardState() != GPSystem.CARD_SECURED) {
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    }
                    Util.arrayCopyNonAtomic(data, (short) 1, buffer, (short) 0, data[0]);
                    apdu.setOutgoingAndSend((short) 0, data[0]);
                    return;
                case 0x07:
                    // get memory info
                    Util.setShort(buffer, (short) 0, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_PERSISTENT));
                    Util.setShort(buffer, (short) 2, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_RESET));
                    Util.setShort(buffer, (short) 4, JCSystem.getAvailableMemory(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT));
                    apdu.setOutgoingAndSend((short) 0, (short) 6);
                    return;
                default:
                    ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
            }
        }
    }

    static short unpad80(byte[] text, short off, short len) {
        short offset = (short) (off + len - 1);
        for (; offset > off && text[offset] == 0; --offset) {
        }
        if (text[offset] != -128) {
            SystemException.throwIt(SystemException.ILLEGAL_VALUE);
            return 0;
        } else {
            return (short) (offset - off);
        }
    }
}
