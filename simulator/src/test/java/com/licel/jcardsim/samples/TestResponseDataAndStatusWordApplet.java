// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.samples;

import javacard.framework.*;

/**
 * For testing purposes only, simple Applet for testing response data and status word
 * SW1,SW1 will be same value as transmitted APDU P1,P2
 * <p><code>CLA=0x01 INS=0x02 P1=SW1 P2=SW2</code> echo input data</p>
 */
public class TestResponseDataAndStatusWordApplet extends Applet {
    static final byte CLA = (byte) 0x01;
    static final byte INS = (byte) 0x02;

    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        new TestResponseDataAndStatusWordApplet().register();
    }

    @Override
    public void process(APDU apdu) throws ISOException {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();

        if (buffer[ISO7816.OFFSET_CLA] != CLA) {
            ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
        }

        byte P1 = buffer[ISO7816.OFFSET_P1];
        byte P2 = buffer[ISO7816.OFFSET_P2];

        if (buffer[ISO7816.OFFSET_INS] != INS) {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }

        short readCnt = apdu.setIncomingAndReceive();
        short Lc = apdu.getIncomingLength();
        short offsetCData = apdu.getOffsetCdata();
        short read = readCnt;
        while (read < Lc) {
            read += apdu.receiveBytes(read);
        }

        short Ne = apdu.setOutgoing();

        byte[] CDataBytes = JCSystem.makeTransientByteArray(Lc, JCSystem.CLEAR_ON_DESELECT);
        Util.arrayCopyNonAtomic(buffer, offsetCData, CDataBytes, (short) 0, Lc);

        apdu.setOutgoingLength(Ne);
        apdu.sendBytesLong(CDataBytes, (short) 0, Ne);

        short statusWord = Util.makeShort(P1, P2);

        // Force throw exception
        ISOException.throwIt(statusWord);
    }
}
