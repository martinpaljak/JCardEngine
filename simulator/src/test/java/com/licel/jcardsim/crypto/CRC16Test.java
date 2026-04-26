// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.security.Checksum;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for <code>CRC16</code>
 * Test data from NXP JCOP31-36 JavaCard
 */
public class CRC16Test extends SimulatorCoreTest  {

    // etalon msg
    String MESSAGE = "C46A3D01F5494013F9DFF3C5392C64";
    // etalon crc
    String CRC = "0B93";

    /**
     * Test of of class CRC16.
     */
    @Test
    public void testCrc16() {
        System.out.println("test crc16");
        Checksum crcEngine = Checksum.getInstance(Checksum.ALG_ISO3309_CRC16, false);
        byte[] crc = new byte[2];
        byte[] msg = Hex.decode(MESSAGE);
        crcEngine.doFinal(msg, (short) 0, (short) msg.length, crc, (short) 0);
        assertEquals(true, Arrays.areEqual(Hex.decode(CRC), crc));
    }
}
