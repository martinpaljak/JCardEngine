// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.security.Checksum;
import javacard.security.CryptoException;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;

import java.nio.charset.StandardCharsets;

import static org.testng.Assert.*;

public class CRC16Test extends SimulatorCoreTest {

    @Test
    public void testCrc16() {
        Checksum crc = Checksum.getInstance(Checksum.ALG_ISO3309_CRC16, false);
        assertEquals(crc.getAlgorithm(), Checksum.ALG_ISO3309_CRC16);

        // CRC-16/GENIBUS: catalogue "123456789" check value 0xD64E, FCS register seeded to 0xFFFF
        byte[] kat = "123456789".getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[2];
        crc.init(new byte[]{(byte) 0xFF, (byte) 0xFF}, (short) 0, (short) 2);
        crc.doFinal(kat, (short) 0, (short) kat.length, out, (short) 0);
        assertEquals(out, Hex.decode("D64E"));

        // ISO/IEC 3309 resets the seed to 0 after doFinal; vector captured from an NXP JCOP31-36 card
        byte[] msg = Hex.decode("C46A3D01F5494013F9DFF3C5392C64");
        crc.doFinal(msg, (short) 0, (short) msg.length, out, (short) 0);
        assertEquals(out, Hex.decode("0B93"));

        // init rejects a seed that is not the checksum width
        assertThrows(CryptoException.class, () -> crc.init(new byte[]{0}, (short) 0, (short) 1));
    }
}
