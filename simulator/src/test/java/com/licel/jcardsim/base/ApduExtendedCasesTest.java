// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0

package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import apdu4j.core.ResponseAPDU;
import com.licel.jcardsim.samples.ApduExtendedCasesApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.bouncycastle.util.Arrays;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class ApduExtendedCasesTest {

    private static final int CLA = 0x80;
    private static final int INS = 0xb4;
    private static final int P1 = 0x00;
    private static final int P2 = 0x00;
    byte[] appletAIDBytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};

    @Test
    public void testApduCase2_Request256BytesWithLeZeroValue() {
        Simulator instance = getReadySimulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(sel.getSW(), 0x9000);

            var response = bibo.transmit(new CommandAPDU(CLA, INS, P1, P2, 256));
            assertEquals((short) response.getSW(), ISO7816.SW_NO_ERROR);

            // Check content
            byte[] data = response.getData();
            for (short i = 0; i < 256; i++) {
                assertEquals(data[i], (byte) 0x5a);
            }
        }
    }

    @Test
    public void testApduCase2E_Request256BytesWith3ByteLe() {
        Simulator instance = getReadySimulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(sel.getSW(), 0x9000);

            //  Le = 0x00, 0x01,0x00 -> 256
            var response = bibo.transmit(new CommandAPDU(CLA, INS, P1, P2, 256));
            assertEquals((short) response.getSW(), ISO7816.SW_NO_ERROR);

            // Check content
            byte[] data = response.getData();
            for (short i = 0; i < 256; i++) {
                assertEquals(data[i], (byte) 0x5a);
            }
        }
    }

    @Test
    public void testApduCase3E_Send256Bytes() {
        Simulator instance = getReadySimulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(sel.getSW(), 0x9000);

            //  Lc = 0x00, 0x01,0x00 -> 256
            byte[] data = new byte[256];
            Arrays.fill(data, (byte) 0x5a);

            var response = bibo.transmit(new CommandAPDU(CLA, INS, P1, P2, data));
            assertEquals((short) response.getSW(), ISO7816.SW_NO_ERROR);
        }
    }

    @Test
    public void testApduCase4_Request256BytesWithLeZeroValue() {
        Simulator instance = getReadySimulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(sel.getSW(), 0x9000);

            var response = bibo.transmit(new CommandAPDU(CLA, INS, P1, P2, new byte[]{0}, 256));
            assertEquals((short) response.getSW(), ISO7816.SW_NO_ERROR);

            // Check content
            byte[] data = response.getData();
            for (short i = 0; i < 256; i++) {
                assertEquals(data[i], (byte) 0x5a);
            }
        }
    }

    @Test
    public void testApduCase4E_Send256BytesAndRequest256Bytes() {
        Simulator instance = getReadySimulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(sel.getSW(), 0x9000);

            byte[] data = new byte[256];
            Arrays.fill(data, (byte) 0x5a);

            var response = bibo.transmit(new CommandAPDU(CLA, INS, P1, P2, data, 256));
            assertEquals((short) response.getSW(), ISO7816.SW_NO_ERROR);

            // Check content
            byte[] respData = response.getData();
            for (short i = 0; i < 256; i++) {
                assertEquals(respData[i], (byte) 0x5a);
            }
        }
    }

    @Test
    public void malformedInputRejectedAtTheBoundary() {
        Simulator instance = getReadySimulator();

        try (var bibo = instance.connect()) {
            // null is not a frame, so it is a bad argument rather than a card response
            assertThrows(NullPointerException.class, () -> bibo.transceive(null));
            // Lc announces 2 bytes and 4 follow: neither a case 3 (5+Lc) nor a case 4 (5+Lc+1) frame
            assertEquals(new ResponseAPDU(bibo.transceive(new byte[]{(byte) CLA, (byte) INS, 0, 0, 2, 1, 2, 3, 4})).getSW(), 0x6700);
            // zero Lc byte promises a 3-byte extended Lc, but the header stops one byte short
            assertEquals(new ResponseAPDU(bibo.transceive(new byte[]{(byte) CLA, (byte) INS, 0, 0, 0, 0})).getSW(), 0x6700);
            // extended Lc of zero cannot carry data
            assertEquals(new ResponseAPDU(bibo.transceive(new byte[]{(byte) CLA, (byte) INS, 0, 0, 0, 0, 0, 1, 2})).getSW(), 0x6700);
            // shorter than the mandatory CLA INS P1 P2 header
            assertEquals(new ResponseAPDU(bibo.transceive(new byte[]{(byte) CLA, (byte) INS, 0})).getSW(), 0x6700);
            // the card is untouched, so the first valid command still powers up and selects
            assertEquals(bibo.transmit(AIDUtil.select(AIDUtil.create(appletAIDBytes))).getSW(), 0x9000);
        }
    }

    private Simulator getReadySimulator() {
        Simulator instance = new Simulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        instance.installApplet(appletAID, ApduExtendedCasesApplet.class);
        return instance;
    }
}
