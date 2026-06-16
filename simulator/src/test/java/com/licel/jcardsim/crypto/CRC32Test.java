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

public class CRC32Test extends SimulatorCoreTest {

    @Test
    public void testCrc32() {
        Checksum crc = Checksum.getInstance(Checksum.ALG_ISO3309_CRC32, false);
        assertEquals(crc.getAlgorithm(), Checksum.ALG_ISO3309_CRC32);

        // CRC-32/ISO-HDLC (zlib): catalogue "123456789" check value 0xCBF43926, FCS register seeded to 0xFFFFFFFF
        byte[] kat = "123456789".getBytes(StandardCharsets.US_ASCII);
        byte[] out = new byte[4];
        crc.init(new byte[]{(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF}, (short) 0, (short) 4);
        crc.doFinal(kat, (short) 0, (short) kat.length, out, (short) 0);
        assertEquals(out, Hex.decode("CBF43926"));

        // ISO/IEC 3309 resets the seed to 0 after doFinal; vector captured from an NXP JCOP31-36 card
        byte[] msg = Hex.decode("C46A3D01F5494013F9DFF3C5392C64");
        crc.doFinal(msg, (short) 0, (short) msg.length, out, (short) 0);
        assertEquals(out, Hex.decode("C6A5A2E4"));

        // init rejects a seed that is not the checksum width
        assertThrows(CryptoException.class, () -> crc.init(new byte[]{0}, (short) 0, (short) 1));
    }
}
