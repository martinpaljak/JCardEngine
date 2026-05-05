// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0

package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.ApduExtendedCasesApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

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
            assertEquals(0x9000, sel.getSW());

            var response = bibo.transmit(new CommandAPDU(CLA, INS, P1, P2, 256));
            assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

            // Check content
            byte[] data = response.getData();
            for (short i = 0; i < 256; i++) {
                assertEquals((byte) 0x5a, data[i]);
            }
        }
    }

    @Test
    public void testApduCase2E_Request256BytesWith3ByteLe() {
        Simulator instance = getReadySimulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(0x9000, sel.getSW());

            //  Le = 0x00, 0x01,0x00 -> 256
            var response = bibo.transmit(new CommandAPDU(CLA, INS, P1, P2, 256));
            assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

            // Check content
            byte[] data = response.getData();
            for (short i = 0; i < 256; i++) {
                assertEquals((byte) 0x5a, data[i]);
            }
        }
    }

    @Test
    public void testApduCase3E_Send256Bytes() {
        Simulator instance = getReadySimulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(0x9000, sel.getSW());

            //  Lc = 0x00, 0x01,0x00 -> 256
            byte[] data = new byte[256];
            Arrays.fill(data, (byte) 0x5a);

            var response = bibo.transmit(new CommandAPDU(CLA, INS, P1, P2, data));
            assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());
        }
    }

    @Test
    public void testApduCase4_Request256BytesWithLeZeroValue() {
        Simulator instance = getReadySimulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(0x9000, sel.getSW());

            var response = bibo.transmit(new CommandAPDU(CLA, INS, P1, P2, new byte[]{0}, 256));
            assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

            // Check content
            byte[] data = response.getData();
            for (short i = 0; i < 256; i++) {
                assertEquals((byte) 0x5a, data[i]);
            }
        }
    }

    @Test
    public void testApduCase4E_Send256BytesAndRequest256Bytes() {
        Simulator instance = getReadySimulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        try (var bibo = instance.connect()) {
            var sel = bibo.transmit(AIDUtil.select(appletAID));
            assertEquals(0x9000, sel.getSW());

            byte[] data = new byte[256];
            Arrays.fill(data, (byte) 0x5a);

            var response = bibo.transmit(new CommandAPDU(CLA, INS, P1, P2, data, 256));
            assertEquals(ISO7816.SW_NO_ERROR, (short) response.getSW());

            // Check content
            byte[] respData = response.getData();
            for (short i = 0; i < 256; i++) {
                assertEquals((byte) 0x5a, respData[i]);
            }
        }
    }

    private Simulator getReadySimulator() {
        Simulator instance = new Simulator();
        AID appletAID = AIDUtil.create(appletAIDBytes);

        instance.installApplet(appletAID, ApduExtendedCasesApplet.class);
        return instance;
    }
}
