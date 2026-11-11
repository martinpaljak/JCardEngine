// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;
import javacard.security.HMACKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

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
        assertFalse(desKey.isInitialized());
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
        assertTrue(desKey.isInitialized());
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
        assertEquals(testKey, key);
        // JC 3.2 HMACKey.getKey returns -1 above 127 bytes
        HMACKey hmac = (HMACKey) KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) 1600, false);
        byte[] secret = new byte[200];
        Util.arrayFillNonAtomic(secret, (short) 0, (short) secret.length, (byte) 9);
        hmac.setKey(secret, (short) 0, (short) secret.length);
        byte[] out = new byte[200];
        assertEquals(hmac.getKey(out, (short) 0), (byte) -1);
        assertEquals(out, secret);
        // JC 3.2 HMACKey: any length aligned on a multiple of 8 bits
        assertEquals(expectThrows(CryptoException.class, () -> KeyBuilder.buildKey(KeyBuilder.TYPE_HMAC, (short) 12, false)).getReason(), CryptoException.NO_SUCH_ALGORITHM);
    }

    @Test
    public void testGetMemoryType() {
        Key desKey = KeyBuilder.buildKey(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES, false);
        assertEquals(KeyBuilder.getMemoryType(desKey), JCSystem.MEMORY_TYPE_PERSISTENT);
        // a foreign Key instance throws CryptoException, not ClassCastException
        Key foreign = new Key() {
            @Override
            public byte getType() {
                return KeyBuilder.TYPE_DES;
            }

            @Override
            public short getSize() {
                return KeyBuilder.LENGTH_DES;
            }

            @Override
            public boolean isInitialized() {
                return false;
            }

            @Override
            public void clearKey() {
            }
        };
        CryptoException e = expectThrows(CryptoException.class, () -> KeyBuilder.getMemoryType(foreign));
        assertEquals(e.getReason(), CryptoException.ILLEGAL_VALUE);
    }
}
