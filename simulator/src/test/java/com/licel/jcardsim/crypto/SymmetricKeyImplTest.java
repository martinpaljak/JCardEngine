// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

/**
 * Test for <code>SymmetricKeyImpl</code>
 */
public class SymmetricKeyImplTest extends SimulatorCoreTest {

    /**
     * Test of clearKey method, of class SymmetricKeyImpl.
     */
    @Test
    public void testClearKey() {
        SymmetricKeyImpl desKey = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES);
        byte[] key = new byte[8];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        desKey.setKey(key, (short) 0);
        desKey.clearKey();
        assertEquals(false, desKey.isInitialized());
    }

    /**
     * Test of setKey method, of class SymmetricKeyImpl.
     */
    @Test
    public void testSetKey() {
        SymmetricKeyImpl desKey = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES);
        byte[] key = new byte[8];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        desKey.setKey(key, (short) 0);
        assertEquals(true, desKey.isInitialized());
    }

    /**
     * Test of getKey method, of class SymmetricKeyImpl.
     */
    @Test
    public void testGetKey() {
        SymmetricKeyImpl desKey = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES);
        byte[] key = new byte[8];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        desKey.setKey(key, (short) 0);
        byte[] testKey = new byte[8];
        desKey.getKey(testKey, (short) 0);
        assertEquals(true, Arrays.areEqual(testKey, key));
    }
}
