// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import apdu4j.prefs.Preferences;
import com.licel.jcardsim.SimulatorCoreTest;
import com.licel.jcardsim.base.Simulator;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.RandomData;
import org.bouncycastle.util.encoders.Hex;
import org.testng.annotations.Test;
import pro.javacard.engine.JavaCardEngine;

import java.util.Arrays;

import static org.testng.Assert.*;

/**
 * Test for <code>RandomDataImpl</code>
 */
@SuppressWarnings("deprecation")
public class RandomDataImplTest extends SimulatorCoreTest {

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
        assertEquals(len, 4);
        assertFalse(Arrays.equals(new byte[4], data));

        rnd.close();
        // after close(), a further call throws ILLEGAL_USE
        CryptoException e = expectThrows(CryptoException.class, () -> rnd.nextBytes(data, (short) 0, (short) data.length));
        assertEquals(e.getReason(), CryptoException.ILLEGAL_USE);
    }

    // GH #20: building a card with the jcardengine.rng.seed preference seeds the per-card RNG, so
    // RandomData output is fully reproducible. Same seed -> identical stream; different/no seed -> differs.
    @Test
    public void testSeededRngIsDeterministic() {
        // Building a fresh card swaps Simulator.current(); restore the class-level one afterwards so
        // the other tests sharing this SimulatorCoreTest keep a current Engine instance.
        var outer = (Simulator) Simulator.current();
        try {
            // Two cards built with the SAME seed produce identical RandomData output, plus an exact vector.
            byte[] a = generateSeeded(0x0102030405060708L);
            byte[] b = generateSeeded(0x0102030405060708L);
            assertEquals(b, a);
            // Exact byte vector for seed 0x0102030405060708 (DigestRandomGenerator over SHA-1, GH #20 path).
            assertEquals(Hex.toHexString(a), "935299e79c4cca58");

            // A different seed yields a different stream.
            byte[] c = generateSeeded(0x1122334455667788L);
            assertFalse(Arrays.equals(a, c));

            // An unseeded card uses a real SecureRandom, so it differs from the seeded stream too.
            var unseeded = (Simulator) new JavaCardEngine.Builder().build();
            try (var ignored = unseeded.asCurrent()) {
                byte[] d = new byte[8];
                RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(d, (short) 0, (short) d.length);
                assertFalse(Arrays.equals(a, d));
            }
        } finally {
            outer.asCurrent();
        }
    }

    private static byte[] generateSeeded(long seed) {
        var prefs = Preferences.of().with(JavaCardEngine.RNG_SEED, seed);
        var sim = (Simulator) new JavaCardEngine.Builder().preferences(prefs).build();
        try (var ignored = sim.asCurrent()) {
            byte[] out = new byte[8];
            RandomData.getInstance(RandomData.ALG_SECURE_RANDOM).generateData(out, (short) 0, (short) out.length);
            return out;
        }
    }
}
