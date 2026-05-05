// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.*;
import org.globalplatform.GPRegistryEntry;
import org.globalplatform.GPSystem;
import org.globalplatform.Personalization;
import org.globalplatform.SecureChannel;
import pro.javacard.engine.testapplets.testlib.TestLibrary;

public final class GlobalPlatformTestApplet extends Applet implements IdentityShareable, Personalization {

    public static final byte INS_PERSO_DATA    = (byte) 0x01; // perso payload readback
    public static final byte INS_PERSO_AID     = (byte) 0x02; // JCSystem.getAID() captured during processData
    public static final byte INS_PERSO_PREVAID = (byte) 0x03; // JCSystem.getPreviousContextAID() captured
    public static final byte INS_INITIALIZE_UPDATE = 0x50; // GP
    public static final byte INS_EXTERNAL_AUTHENTICATE = ISO7816.INS_EXTERNAL_AUTHENTICATE;
    public static final byte INS_GET_IDENTITY = 0x08;
    public static final byte INS_GET_AID = 0x09;
    public static final byte INS_QUERY_PEER_IDENTITY = 0x0A;
    public static final byte INS_GET_CARD_STATE = (byte) 0x60;
    public static final byte INS_LOCK_CARD = (byte) 0x61;
    public static final byte INS_TERMINATE_CARD = (byte) 0x62;
    public static final byte INS_GET_OWN_LCS = (byte) 0x63;     // own registry entry's lifecycle byte
    public static final byte INS_SET_OWN_LCS = (byte) 0x64;     // GPSystem.setCardContentState(P1)
    public static final byte INS_SET_OWN_LCS_VIA_REGISTRY = (byte) 0x65; // GPSystem.getRegistryEntry(null).setState(P1)
    public static final byte INS_QUERY_AID = (byte) 0xCA;     // GPSystem.getRegistryEntry(<AID from cdata>)
    public static final byte INS_QUERY_SELF = (byte) 0xCB;    // GPSystem.getRegistryEntry(null)

    byte[] data = new byte[128];
    short value = 0;
    byte identity = 0;

    private final byte[] persoData = new byte[256];
    private short persoLen = 0;
    private final byte[] persoAID = new byte[16];
    private short persoAIDLen = 0;
    private final byte[] persoPrevAID = new byte[16];
    private short persoPrevAIDLen = 0;

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short) (bArray[offset] + 1); // instance AID
        offset += (short) (bArray[offset] + 1); // privileges - expect none
        byte paramsLen = bArray[offset];
        byte id = paramsLen > 0 ? bArray[(short) (offset + 1)] : 0;
        GlobalPlatformTestApplet applet = new GlobalPlatformTestApplet(id);
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


    private GlobalPlatformTestApplet(byte id) {
        identity = id;
        value = TestLibrary.valueHelper();
    }

    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        return this;
    }

    @Override
    public byte identity() {
        return identity;
    }

    @Override
    public void deselect() {
        GPSystem.getSecureChannel().resetSecurity();
    }

    @Override
    public boolean select() {
        // NOTE: these are redundant in real life, as OPEN would not allow to select such applet.
        // Here only for test coverage
        byte cs = GPSystem.getCardState();
        if (cs == GPSystem.CARD_LOCKED || cs == GPSystem.CARD_TERMINATED) {
            return false;
        }
        return GPSystem.getCardContentState() == GPSystem.APPLICATION_SELECTABLE;
    }

    @Override
    public short processData(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        // Forwarded STORE DATA: CLA INS P1 P2 Lc data...
        short dataOffset = (short) (inOffset + 5);
        short dataLength = (short) (inBuffer[(short) (inOffset + 4)] & 0xFF);
        Util.arrayCopyNonAtomic(inBuffer, dataOffset, persoData, (short) 0, dataLength);
        persoLen = dataLength;
        AID my = JCSystem.getAID();
        if (my != null) {
            persoAIDLen = my.getBytes(persoAID, (short) 0);
        } else {
            persoAIDLen = 0;
        }
        AID prev = JCSystem.getPreviousContextAID();
        if (prev != null) {
            persoPrevAIDLen = prev.getBytes(persoPrevAID, (short) 0);
        } else {
            persoPrevAIDLen = 0;
        }
        return 0;
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
                    byte cs = GPSystem.getCardState();
                    if (cs == GPSystem.CARD_LOCKED || cs == GPSystem.CARD_TERMINATED) {
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
                case INS_GET_IDENTITY:
                    buffer[0] = identity;
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    return;
                case INS_GET_AID: {
                    short aidLen = JCSystem.getAID().getBytes(buffer, (short) 0);
                    apdu.setOutgoingAndSend((short) 0, aidLen);
                    return;
                }
                case INS_GET_CARD_STATE:
                    buffer[0] = GPSystem.getCardState();
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    return;
                case INS_LOCK_CARD:
                    buffer[0] = (byte) (GPSystem.lockCard() ? 0x01 : 0x00);
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    return;
                case INS_TERMINATE_CARD:
                    buffer[0] = (byte) (GPSystem.terminateCard() ? 0x01 : 0x00);
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    return;
                case INS_GET_OWN_LCS:
                    buffer[0] = GPSystem.getCardContentState();
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    return;
                case INS_SET_OWN_LCS:
                    boolean ok = GPSystem.setCardContentState(buffer[ISO7816.OFFSET_P1]);
                    buffer[0] = (byte) (ok ? 0x01 : 0x00);
                    buffer[1] = GPSystem.getCardContentState();
                    apdu.setOutgoingAndSend((short) 0, (short) 2);
                    return;
                case INS_SET_OWN_LCS_VIA_REGISTRY: {
                    GPRegistryEntry self = GPSystem.getRegistryEntry(null);
                    boolean okR = self != null && self.setState(buffer[ISO7816.OFFSET_P1]);
                    buffer[0] = (byte) (okR ? 0x01 : 0x00);
                    buffer[1] = GPSystem.getCardContentState();
                    apdu.setOutgoingAndSend((short) 0, (short) 2);
                    return;
                }
                case INS_PERSO_DATA: {
                    Util.arrayCopyNonAtomic(persoData, (short) 0, buffer, (short) 0, persoLen);
                    apdu.setOutgoingAndSend((short) 0, persoLen);
                    return;
                }
                case INS_PERSO_AID: {
                    Util.arrayCopyNonAtomic(persoAID, (short) 0, buffer, (short) 0, persoAIDLen);
                    apdu.setOutgoingAndSend((short) 0, persoAIDLen);
                    return;
                }
                case INS_PERSO_PREVAID: {
                    Util.arrayCopyNonAtomic(persoPrevAID, (short) 0, buffer, (short) 0, persoPrevAIDLen);
                    apdu.setOutgoingAndSend((short) 0, persoPrevAIDLen);
                    return;
                }
                case INS_QUERY_PEER_IDENTITY: {
                    short inLen = apdu.setIncomingAndReceive();
                    AID peerAid = JCSystem.lookupAID(buffer, apdu.getOffsetCdata(), (byte) inLen);
                    if (peerAid == null) {
                        ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
                    }
                    Shareable so = JCSystem.getAppletShareableInterfaceObject(peerAid, (byte) 0);
                    if (so == null) {
                        ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
                    }
                    buffer[0] = ((IdentityShareable) so).identity();
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    return;
                }
                case INS_QUERY_SELF: {
                    GPRegistryEntry self = GPSystem.getRegistryEntry(null);
                    if (self == null) {
                        ISOException.throwIt((short) 0x6A82);
                    }
                    buffer[0] = self.getState();
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    return;
                }
                case INS_QUERY_AID: {
                    short lc = apdu.setIncomingAndReceive();
                    if (lc < 5 || lc > 16) {
                        ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
                    }
                    AID target = JCSystem.lookupAID(buffer, apdu.getOffsetCdata(), (byte) lc);
                    if (target == null) {
                        ISOException.throwIt((short) 0x6A82);
                    }
                    GPRegistryEntry entry = GPSystem.getRegistryEntry(target);
                    if (entry == null) {
                        ISOException.throwIt((short) 0x6A82);
                    }
                    buffer[0] = entry.getState();
                    apdu.setOutgoingAndSend((short) 0, (short) 1);
                    return;
                }
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
