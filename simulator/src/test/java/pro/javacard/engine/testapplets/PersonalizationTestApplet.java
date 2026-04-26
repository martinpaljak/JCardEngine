// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-License-Identifier: Apache-2.0
package pro.javacard.engine.testapplets;

import javacard.framework.*;
import org.globalplatform.Personalization;

public class PersonalizationTestApplet extends Applet implements Personalization {

    private byte[] storedData = new byte[256];
    private short storedLength = 0;

    // Captured context AIDs during processData() - for verifying GP 2.2.1 Section 7.3.3 context switch
    private byte[] capturedAID = new byte[16];
    private short capturedAIDLen = 0;
    private byte[] capturedPreviousAID = new byte[16];
    private short capturedPreviousAIDLen = 0;

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        new PersonalizationTestApplet().register(bArray, (short) (bOffset + 1), bArray[bOffset]);
    }

    @Override
    public short processData(byte[] inBuffer, short inOffset, short inLength, byte[] outBuffer, short outOffset) {
        // The forwarded STORE DATA command: CLA(0) INS(1) P1(2) P2(3) Lc(4) data(5..)
        short dataOffset = (short) (inOffset + 5);
        short dataLength = (short) (inBuffer[(short) (inOffset + 4)] & 0xFF);
        Util.arrayCopyNonAtomic(inBuffer, dataOffset, storedData, (short) 0, dataLength);
        storedLength = dataLength;

        // Capture JCSystem.getAID() - per GP spec, should be this applet's AID after context switch
        AID myAID = JCSystem.getAID();
        if (myAID != null) {
            capturedAIDLen = myAID.getBytes(capturedAID, (short) 0);
        } else {
            capturedAIDLen = 0;
        }

        // Capture JCSystem.getPreviousContextAID() - per GP spec, should be the Security Domain's AID
        AID prevAID = JCSystem.getPreviousContextAID();
        if (prevAID != null) {
            capturedPreviousAIDLen = prevAID.getBytes(capturedPreviousAID, (short) 0);
        } else {
            capturedPreviousAIDLen = 0;
        }

        return 0;
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }
        byte[] buffer = apdu.getBuffer();
        switch (buffer[ISO7816.OFFSET_INS]) {
            case (byte) 0x01:
                // Read stored personalization data
                Util.arrayCopyNonAtomic(storedData, (short) 0, buffer, (short) 0, storedLength);
                apdu.setOutgoingAndSend((short) 0, storedLength);
                break;
            case (byte) 0x02:
                // Read captured JCSystem.getAID() from processData()
                Util.arrayCopyNonAtomic(capturedAID, (short) 0, buffer, (short) 0, capturedAIDLen);
                apdu.setOutgoingAndSend((short) 0, capturedAIDLen);
                break;
            case (byte) 0x03:
                // Read captured JCSystem.getPreviousContextAID() from processData()
                Util.arrayCopyNonAtomic(capturedPreviousAID, (short) 0, buffer, (short) 0, capturedPreviousAIDLen);
                apdu.setOutgoingAndSend((short) 0, capturedPreviousAIDLen);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
}
