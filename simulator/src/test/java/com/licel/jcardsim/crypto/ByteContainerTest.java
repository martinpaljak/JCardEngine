// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2014 Robert Bachmann
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import org.testng.annotations.Test;

import java.math.BigInteger;

import static org.testng.Assert.*;

public class ByteContainerTest extends SimulatorCoreTest {
    @Test
    public void testPositiveIntegerWithLeadingZero() {
        BigInteger expected = new BigInteger("4720643197658441292834747278018339");
        assertTrue(expected.toByteArray()[0] == 0);
        checkRoundTrip(expected);
    }

    @Test
    public void testPositiveIntegerWithoutLeadingZero() {
        BigInteger expected = new BigInteger("5192296858534827689835882578830703");
        assertTrue(expected.toByteArray()[0] != 0);
        checkRoundTrip(expected);
    }

    @Test
    public void testZero() {
        BigInteger expected = new BigInteger("0");
        assertTrue(expected.toByteArray()[0] == 0);
        checkRoundTrip(expected);
    }

    @Test
    public void testNegativeNumber() {
        BigInteger expected = new BigInteger("-123");

        // pinned container rejects a negative value
        ByteContainer neg = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, 4);
        assertThrows(IllegalArgumentException.class, () -> neg.setBigInteger(expected));

        // 0x0102 requires 2 bytes; pinned to width 1 must reject it
        ByteContainer narrow = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, 1);
        assertThrows(CryptoException.class, () -> narrow.setBigInteger(BigInteger.valueOf(0x0102)));

        // 0x0102 in a 4-byte pinned container pads to 00 00 01 02
        ByteContainer c = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, 4);
        c.setBigInteger(BigInteger.valueOf(0x0102));
        byte[] buf = new byte[4];
        assertEquals(c.getBytes(buf, (short) 0), 4);
        assertEquals(buf, new byte[]{0x00, 0x00, 0x01, 0x02});
    }

    @Test
    public void testMinimalReadback() {
        // fixed-capacity buffer reporting significant length, as used for RSA public exponent
        ByteContainer e = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, 4, true);
        e.setBigInteger(BigInteger.valueOf(0x010001));
        byte[] buf = new byte[4];
        // 0x010001 reads back as 3 significant bytes, not the 4-byte capacity
        assertEquals(e.getBytes(buf, (short) 0), 3);
        assertEquals(buf, new byte[]{0x01, 0x00, 0x01, 0x00});
        assertEquals(e.getBigInteger(), BigInteger.valueOf(0x010001));
        // setting a shorter value reports the new value's length
        e.setBigInteger(BigInteger.valueOf(0x03));
        assertEquals(e.getBytes(buf, (short) 0), 1);
        assertEquals(e.getBigInteger(), BigInteger.valueOf(0x03));
    }

    private void checkRoundTrip(BigInteger expected) {
        // a minimal-readback container stores and returns the value at its own length
        int mlen = Math.max(1, (expected.bitLength() + 7) / 8);
        ByteContainer minimal = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, mlen + 2, true);
        minimal.setBigInteger(expected);
        assertEquals(minimal.getBigInteger(), expected);

        // pinned container left-pads to the exact width
        int width = expected.bitLength() / 8 + 3;
        ByteContainer padded = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, width);
        padded.setBigInteger(expected);
        byte[] buf = new byte[width];
        assertEquals(padded.getBytes(buf, (short) 0), width);
        assertEquals(new BigInteger(1, buf), expected);
    }
}
