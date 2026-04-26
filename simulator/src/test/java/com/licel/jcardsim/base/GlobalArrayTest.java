// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.base;

import com.licel.jcardsim.samples.GlobalArrayClientApplet;
import com.licel.jcardsim.samples.GlobalArrayServerApplet;
import com.licel.jcardsim.utils.AIDUtil;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import javacard.framework.Util;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInstance;

import static org.junit.jupiter.api.Assertions.*;

@TestInstance(TestInstance.Lifecycle.PER_CLASS)
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

    @BeforeAll
    protected void setUp() throws Exception {
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
        assertEquals(serverAppletAID, instance.installApplet(serverAppletAID, GlobalArrayServerApplet.class));
        assertEquals(clientAppletAID, instance.installApplet(clientAppletAID, GlobalArrayClientApplet.class, clientAppletPar));

        // Select server applet
        assertTrue(instance.selectApplet(serverAppletAID));

        // Send C-APDU to create the byte global array for 32-byte size and filled with 0x5A
        byte[] response1 = instance.transceive(new byte[]{0x10, 0x01, 32, (byte) 0x5A});

        // Check command succeeded
        assertEquals(ISO7816.SW_NO_ERROR, Util.getShort(response1, (short) 0));

        // Select client applet
        assertTrue(instance.selectApplet(clientAppletAID));
        // Send C-APDU to read the global byte array for 32 bytes
        byte[] response2 = instance.transceive(new byte[]{0x10, 0x01, 0x00, 0x00, 32});
        // Check command succeeded
        assertEquals(ISO7816.SW_NO_ERROR, Util.getShort(response2, (short) 32));

        // Check global array content
        for (byte i = 0; i < 32; i++) {
            assertEquals((byte) 0x5A, ((byte[]) response2)[i]);
        }

        // Create C-APDU to write 32 test bytes to global array
        byte[] commandAPDUHeaderWithLc = new byte[]{0x10, 0x02, 0, 0, 32};
        byte[] sendAPDU = new byte[5 + 32];
        System.arraycopy(commandAPDUHeaderWithLc, 0, sendAPDU, 0, 5);
        System.arraycopy(bytesForTest, 0, sendAPDU, 5, 32);

        // Send C-APDU
        byte[] response3 = instance.transceive(sendAPDU);
        // Check command succeeded
        assertEquals(ISO7816.SW_NO_ERROR, Util.getShort(response3, (short) 0));

        // Send C-APDU to read the global byte array for 32 bytes
        byte[] response4 = instance.transceive(new byte[]{0x10, 0x01, 0x00, 0x00, 32});
        // Check command succeeded
        assertEquals(ISO7816.SW_NO_ERROR, Util.getShort(response4, (short) 32));

        // Check the global array with the writen data
        byte[] globalArrayBytes = new byte[32];
        System.arraycopy(response4, 0, globalArrayBytes, 0, globalArrayBytes.length);
        assertArrayEquals(bytesForTest, globalArrayBytes);
    }
}
