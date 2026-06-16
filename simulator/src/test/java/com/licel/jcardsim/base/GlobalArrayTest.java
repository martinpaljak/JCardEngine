// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import apdu4j.core.CommandAPDU;
import com.licel.jcardsim.samples.GlobalArrayClientApplet;
import com.licel.jcardsim.samples.GlobalArrayServerApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

public class GlobalArrayTest {
    byte[] serverAppletAIDBytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09};
    byte[] wrongServerAppletAIDBytes = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x00};
    AID serverAppletAID;

    String clientAppletAIDStr;
    AID clientAppletAID;
    byte[] clientAppletPar = null;

    byte[] bytesForTest = null;
    boolean[] booleansForTest = null;
    short[] shortsForTest = null;

    @BeforeClass
    public void setUp() throws Exception {
        serverAppletAID = AIDUtil.create(serverAppletAIDBytes);
        clientAppletAIDStr = "090807060504030201";
        clientAppletAID = AIDUtil.create(clientAppletAIDStr);
        clientAppletPar = serverAppletAIDBytes.clone();

        bytesForTest = new byte[32];
        for (byte i = 0; i < 32; i++) {
            bytesForTest[i] = i;
        }

        booleansForTest = new boolean[32];
        for (byte i = 0; i < 32; i++) {
            if ((i % 2) != 0) {
                booleansForTest[i] = true;
            } else {
                booleansForTest[i] = true;
            }
        }

        shortsForTest = new short[32];
        for (byte i = 0; i < 32; i++) {
            shortsForTest[i] = i;
        }
    }

    /**
     * Test access the global byte array with the client applet
     */
    @Test
    public void testAccessGlobalArrayByteByClientApplet() {
        Simulator instance = new Simulator();

        // Install server and client applet
        assertEquals(instance.installApplet(serverAppletAID, GlobalArrayServerApplet.class), serverAppletAID);
        assertEquals(instance.installApplet(clientAppletAID, GlobalArrayClientApplet.class, clientAppletPar), clientAppletAID);

        try (var bibo = instance.connect()) {
            // Select server applet
            var sel1 = bibo.transmit(AIDUtil.select(serverAppletAID));
            assertEquals(sel1.getSW(), 0x9000);

            // Send C-APDU to create the byte global array for 32-byte size and filled with 0x5A
            var response1 = bibo.transmit(new CommandAPDU(0x10, 0x01, 32, 0x5A));

            // Check command succeeded
            assertEquals((short) response1.getSW(), ISO7816.SW_NO_ERROR);

            // Select client applet
            var sel2 = bibo.transmit(AIDUtil.select(clientAppletAID));
            assertEquals(sel2.getSW(), 0x9000);
            // Send C-APDU to read the global byte array for 32 bytes
            var response2 = bibo.transmit(new CommandAPDU(0x10, 0x01, 0x00, 0x00, 32));
            // Check command succeeded
            assertEquals((short) response2.getSW(), ISO7816.SW_NO_ERROR);

            // Check global array content
            byte[] response2Data = response2.getData();
            for (byte i = 0; i < 32; i++) {
                assertEquals(response2Data[i], (byte) 0x5A);
            }

            // Send C-APDU to write 32 test bytes to global array
            var response3 = bibo.transmit(new CommandAPDU(0x10, 0x02, 0x00, 0x00, bytesForTest));
            // Check command succeeded
            assertEquals((short) response3.getSW(), ISO7816.SW_NO_ERROR);

            // Send C-APDU to read the global byte array for 32 bytes
            var response4 = bibo.transmit(new CommandAPDU(0x10, 0x01, 0x00, 0x00, 32));
            // Check command succeeded
            assertEquals((short) response4.getSW(), ISO7816.SW_NO_ERROR);

            // Check the global array with the writen data
            assertEquals(response4.getData(), bytesForTest);
        }
    }
}
