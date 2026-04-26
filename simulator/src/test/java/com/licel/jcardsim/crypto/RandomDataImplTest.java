// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.Util;
import javacard.security.RandomData;
import org.junit.jupiter.api.Test;

import java.util.Arrays;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for <code>RandomDataImpl</code>
 */
@SuppressWarnings("deprecation")
public class RandomDataImplTest {

    /**
     * Test of generateData method, of class RandomDataImpl.
     */
    @Test
    public void testGenerateData() {
        System.out.println("generateData");
        byte[] buffer0 = new byte[]{0,0,0,0,0,0,0,0};
        byte[] buffer1 = new byte[]{0,0,0,0,0,0,0,0};

        RandomData instance = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        instance.generateData(buffer0, (short) 0, (short) buffer0.length);
        assertTrue( 0 != Util.arrayCompare(buffer0, (short) 0,buffer1, (short) 0, (short) buffer0.length));

        instance = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        instance.generateData(buffer1, (short) 0, (short) buffer1.length);
        assertTrue( 0 != Util.arrayCompare(buffer0, (short) 0,buffer1, (short) 0, (short) buffer0.length));

        instance = RandomData.getInstance(RandomData.ALG_TRNG);
        instance.generateData(buffer0, (short) 0, (short) buffer0.length);
        assertTrue( 0 != Util.arrayCompare(buffer0, (short) 0,buffer1, (short) 0, (short) buffer0.length));

        instance = RandomData.getInstance(RandomData.ALG_FAST);
        instance.generateData(buffer1, (short) 0, (short) buffer1.length);
        assertTrue( 0 != Util.arrayCompare(buffer0, (short) 0,buffer1, (short) 0, (short) buffer0.length));

        instance = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        instance.generateData(buffer0, (short) 0, (short) buffer0.length);
        assertTrue( 0 != Util.arrayCompare(buffer0, (short) 0,buffer1, (short) 0, (short) buffer0.length));

    }

    /**
     * Test of generateData method, of class RandomDataImpl.
     */
    @Test
    public void testNextBytes() {
        System.out.println("nextBytes");
        byte[] buffer0 = new byte[]{0,0,0,0,0,0,0,0};
        byte[] buffer1 = new byte[]{0,0,0,0,0,0,0,0};

        RandomData instance = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        instance.nextBytes(buffer0, (short) 0, (short) buffer0.length);
        assertTrue( 0 != Util.arrayCompare(buffer0, (short) 0,buffer1, (short) 0, (short) buffer0.length));

        instance = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        instance.nextBytes(buffer1, (short) 0, (short) buffer1.length);
        assertTrue( 0 != Util.arrayCompare(buffer0, (short) 0,buffer1, (short) 0, (short) buffer0.length));

        instance = RandomData.getInstance(RandomData.ALG_TRNG);
        instance.nextBytes(buffer0, (short) 0, (short) buffer0.length);
        assertTrue( 0 != Util.arrayCompare(buffer0, (short) 0,buffer1, (short) 0, (short) buffer0.length));

        instance = RandomData.getInstance(RandomData.ALG_FAST);
        instance.nextBytes(buffer1, (short) 0, (short) buffer1.length);
        assertTrue( 0 != Util.arrayCompare(buffer0, (short) 0,buffer1, (short) 0, (short) buffer0.length));

        instance = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        instance.nextBytes(buffer0, (short) 0, (short) buffer0.length);
        assertTrue( 0 != Util.arrayCompare(buffer0, (short) 0,buffer1, (short) 0, (short) buffer0.length));
    }

    /**
     * Test of setSeed method, of class RandomDataImpl.
     */
    @Test
    public void testSetSeed() {
        System.out.println("setSeed");
        byte[] buffer = new byte[8];
        RandomData instance = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        instance.setSeed(buffer, (short) 0, (short) buffer.length);
        instance.generateData(buffer, (short) 0, (short) buffer.length);
        instance = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        instance.setSeed(buffer, (short) 0, (short) buffer.length);
        instance.generateData(buffer, (short) 0, (short) buffer.length);
        instance = RandomData.getInstance(RandomData.ALG_TRNG);
        instance.setSeed(buffer, (short) 0, (short) buffer.length);
        instance.generateData(buffer, (short) 0, (short) buffer.length);
        instance = RandomData.getInstance(RandomData.ALG_FAST);
        instance.setSeed(buffer, (short) 0, (short) buffer.length);
        instance.generateData(buffer, (short) 0, (short) buffer.length);
        instance = RandomData.getInstance(RandomData.ALG_KEYGENERATION);
        instance.setSeed(buffer, (short) 0, (short) buffer.length);
        instance.generateData(buffer, (short) 0, (short) buffer.length);
    }
    @Test
    public void testOneShot() {
        RandomData.OneShot rnd = RandomData.OneShot.open(RandomData.ALG_TRNG);
        assertNotNull(rnd);
        byte[] data = new byte[4];

        short len = rnd.nextBytes(data, (short) 0, (short)data.length);
        assertEquals(4, len);
        assertFalse(Arrays.equals(new byte[4], data));
    }
}
