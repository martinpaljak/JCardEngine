// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.*;
import org.globalplatform.CVM;
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
    public static final byte INS_QUERY_PRIVS = (byte) 0x0B;   // getRegistryEntry(null).getPrivileges(buf, off)
    public static final byte INS_SIO_AIDS = (byte) 0x0C; // AIDs captured during getShareableInterfaceObject
    public static final byte INS_SC_CONTRACT = (byte) 0x0D; // SecureChannel unwrap/wrap/encryptData outcomes
    // Global PIN CVM driver. P1 sub-op: 0 status, 1 setTryLimit(P2), 2 update, 3 verify, 4 block,
    // 5 resetAndUnblock, 6 reset. P2 carries the CVM format (0 -> FORMAT_HEX) for update/verify.
    public static final byte INS_CVM = (byte) 0x66;

    byte[] data = new byte[128];
    short value = 0;
    byte identity = 0;
    boolean rejectSelect = false;

    private final byte[] persoData = new byte[256];
    private short persoLen = 0;
    private final byte[] persoAID = new byte[16];
    private short persoAIDLen = 0;
    private final byte[] persoPrevAID = new byte[16];
    private short persoPrevAIDLen = 0;

    // Fires on every getShareableInterfaceObject call, not just install, unlike the perso fields above.
    private final byte[] sioAID = new byte[16];
    private short sioAIDLen = 0;
    private final byte[] sioClientAID = new byte[16];
    private short sioClientAIDLen = 0;

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        short offset = bOffset;
        offset += (short) (bArray[offset] + 1); // instance AID
        offset += (short) (bArray[offset] + 1); // privileges - expect none
        byte paramsLen = bArray[offset];
        byte id = paramsLen > 0 ? bArray[(short) (offset + 1)] : 0;
        // Second param byte, when non-zero, makes select() refuse selection.
        boolean rejectSelect = paramsLen > 1 && bArray[(short) (offset + 2)] != 0;
        GlobalPlatformTestApplet applet = new GlobalPlatformTestApplet(id, rejectSelect);
        if (JCSystem.getAID() != null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }
        if (JCSystem.getPreviousContextAID() == null) {
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


    private GlobalPlatformTestApplet(byte id, boolean rejectSelect) {
        identity = id;
        this.rejectSelect = rejectSelect;
        value = TestLibrary.valueHelper();
    }

    @Override
    public Shareable getShareableInterfaceObject(AID clientAID, byte parameter) {
        AID my = JCSystem.getAID();
        if (my != null) {
            sioAIDLen = my.getBytes(sioAID, (short) 0);
        } else {
            sioAIDLen = 0;
        }
        if (clientAID != null) {
            sioClientAIDLen = clientAID.getBytes(sioClientAID, (short) 0);
        } else {
            sioClientAIDLen = 0;
        }
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
        if (rejectSelect) {
            return false;
        }
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
                case INS_SC_CONTRACT: {
                    // What the SecureChannel answers for a command carrying no secure messaging:
                    // unwrap length, wrap length, encryptData outcome. A status word thrown by any of
                    // them is reported in place of the length.
                    SecureChannel sc = GPSystem.getSecureChannel();
                    short inlen = apdu.setIncomingAndReceive();
                    short cmdlen = (short) (apdu.getOffsetCdata() + inlen);
                    short unwrapRc;
                    try {
                        unwrapRc = sc.unwrap(buffer, (short) 0, cmdlen);
                    } catch (ISOException e) {
                        unwrapRc = e.getReason();
                    }
                    // wrap() input: four data bytes plus the status bytes an application appends for it to protect
                    Util.arrayFillNonAtomic(buffer, (short) 32, (short) 4, (byte) 0x5A);
                    Util.setShort(buffer, (short) 36, (short) 0x9000);
                    short wrapRc;
                    try {
                        wrapRc = sc.wrap(buffer, (short) 32, (short) 6);
                    } catch (ISOException e) {
                        wrapRc = e.getReason();
                    }
                    short encRc;
                    try {
                        encRc = sc.encryptData(buffer, (short) 32, (short) 16);
                    } catch (ISOException e) {
                        encRc = e.getReason();
                    }
                    // wrap() over a null buffer, reported as 0xFFFF when it threw NullPointerException
                    short nullRc = (short) 0xFFFF;
                    try {
                        nullRc = sc.wrap(null, (short) 0, (short) 6);
                    } catch (NullPointerException e) {
                        // reported as the sentinel above
                    }
                    Util.setShort(buffer, (short) 0, unwrapRc);
                    Util.setShort(buffer, (short) 2, wrapRc);
                    Util.setShort(buffer, (short) 4, encRc);
                    Util.setShort(buffer, (short) 6, nullRc);
                    apdu.setOutgoingAndSend((short) 0, (short) 8);
                    return;
                }
                case INS_SIO_AIDS: {
                    short off = 0;
                    buffer[off++] = (byte) sioAIDLen;
                    Util.arrayCopyNonAtomic(sioAID, (short) 0, buffer, off, sioAIDLen);
                    off += sioAIDLen;
                    buffer[off++] = (byte) sioClientAIDLen;
                    Util.arrayCopyNonAtomic(sioClientAID, (short) 0, buffer, off, sioClientAIDLen);
                    off += sioClientAIDLen;
                    apdu.setOutgoingAndSend((short) 0, off);
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
                case INS_QUERY_PRIVS: {
                    // org.globalplatform GPRegistryEntry.getPrivileges(byte[], short): own 3-byte privilege bitmap.
                    short end = GPSystem.getRegistryEntry(null).getPrivileges(buffer, (short) 0);
                    apdu.setOutgoingAndSend((short) 0, end);
                    return;
                }
                case INS_CVM: {
                    CVM cvm = GPSystem.getCVM(GPSystem.CVM_GLOBAL_PIN);
                    byte fmt = buffer[ISO7816.OFFSET_P2] == 0 ? CVM.FORMAT_HEX : buffer[ISO7816.OFFSET_P2];
                    switch (buffer[ISO7816.OFFSET_P1]) {
                        case 0x00:
                            buffer[0] = (byte) (cvm.isActive() ? 1 : 0);
                            buffer[1] = (byte) (cvm.isSubmitted() ? 1 : 0);
                            buffer[2] = (byte) (cvm.isVerified() ? 1 : 0);
                            buffer[3] = (byte) (cvm.isBlocked() ? 1 : 0);
                            buffer[4] = cvm.getTriesRemaining();
                            apdu.setOutgoingAndSend((short) 0, (short) 5);
                            return;
                        case 0x01:
                            buffer[0] = (byte) (cvm.setTryLimit(buffer[ISO7816.OFFSET_P2]) ? 1 : 0);
                            apdu.setOutgoingAndSend((short) 0, (short) 1);
                            return;
                        case 0x02: {
                            short lc = apdu.setIncomingAndReceive();
                            buffer[0] = (byte) (cvm.update(buffer, apdu.getOffsetCdata(), (byte) lc, fmt) ? 1 : 0);
                            apdu.setOutgoingAndSend((short) 0, (short) 1);
                            return;
                        }
                        case 0x03: {
                            short lc = apdu.setIncomingAndReceive();
                            short r = cvm.verify(buffer, apdu.getOffsetCdata(), (byte) lc, fmt);
                            Util.setShort(buffer, (short) 0, r);
                            buffer[2] = (byte) (cvm.isVerified() ? 1 : 0);
                            buffer[3] = cvm.getTriesRemaining();
                            apdu.setOutgoingAndSend((short) 0, (short) 4);
                            return;
                        }
                        case 0x04:
                            buffer[0] = (byte) (cvm.blockState() ? 1 : 0);
                            apdu.setOutgoingAndSend((short) 0, (short) 1);
                            return;
                        case 0x05:
                            buffer[0] = (byte) (cvm.resetAndUnblockState() ? 1 : 0);
                            apdu.setOutgoingAndSend((short) 0, (short) 1);
                            return;
                        case 0x06:
                            buffer[0] = (byte) (cvm.resetState() ? 1 : 0);
                            apdu.setOutgoingAndSend((short) 0, (short) 1);
                            return;
                        default:
                            ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
                    }
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
