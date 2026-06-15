// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import org.bouncycastle.util.Arrays;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Test for <code>SymmetricKeyImpl</code>
 */
public class SymmetricKeyImplTest extends SimulatorCoreTest {

    /**
     * Test of clearKey method, of class SymmetricKeyImpl.
     */
    @Test
    public void testClearKey() {
        SymmetricKeyImpl desKey = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, JCSystem.MEMORY_TYPE_PERSISTENT);
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
        SymmetricKeyImpl desKey = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, JCSystem.MEMORY_TYPE_PERSISTENT);
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
        SymmetricKeyImpl desKey = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, JCSystem.MEMORY_TYPE_PERSISTENT);
        byte[] key = new byte[8];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        desKey.setKey(key, (short) 0);
        byte[] testKey = new byte[8];
        desKey.getKey(testKey, (short) 0);
        assertEquals(true, Arrays.areEqual(testKey, key));
    }

    @Test
    public void testGetMemoryType() {
        Key desKey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
        assertEquals(JCSystem.MEMORY_TYPE_PERSISTENT, KeyBuilder.getMemoryType(desKey));
        // a foreign Key instance throws CryptoException, not ClassCastException
        Key foreign = new Key() {
            public byte getType() {
                return KeyBuilder.TYPE_DES;
            }

            public short getSize() {
                return KeyBuilder.LENGTH_DES;
            }

            public boolean isInitialized() {
                return false;
            }

            public void clearKey() {
            }
        };
        CryptoException e = assertThrows(CryptoException.class, () -> KeyBuilder.getMemoryType(foreign));
        assertEquals(CryptoException.ILLEGAL_VALUE, e.getReason());
    }
}
