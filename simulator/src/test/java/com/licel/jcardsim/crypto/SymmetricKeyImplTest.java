// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.Util;
import javacard.security.AESKey;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.DESedeEngine;
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
        System.out.println("clearKey");
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
        System.out.println("setKey");
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
        System.out.println("getKey");
        SymmetricKeyImpl desKey = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES);
        byte[] key = new byte[8];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        desKey.setKey(key, (short) 0);
        byte[] testKey = new byte[8];
        desKey.getKey(testKey, (short) 0);
        assertEquals(true, Arrays.areEqual(testKey, key));
    }

    /**
     * Test of getCipher method, of class SymmetricKeyImpl.
     */
    @Test
    public void testGetCipher() {
        System.out.println("getCipher");
        // des key
        SymmetricKeyImpl desKey = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES);
        byte[] key = new byte[8];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        desKey.setKey(key, (short) 0);
        boolean isValidCipher = desKey.getCipher() instanceof DESEngine;
        assertEquals(true, isValidCipher);
        // 3des key
        SymmetricKeyImpl des3Key = new SymmetricKeyImpl(KeyBuilder.TYPE_DES, KeyBuilder.LENGTH_DES3_3KEY);
        key = new byte[24];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        des3Key.setKey(key, (short) 0);
        isValidCipher = des3Key.getCipher() instanceof DESedeEngine;
        assertEquals(true, isValidCipher);
        // aes key - 128
        AESKey aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        key = new byte[16];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        aesKey.setKey(key, (short) 0);
        // aes key - 192
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_192, false);
        key = new byte[24];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        aesKey.setKey(key, (short) 0);
        // aes key - 256
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        key = new byte[32];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        aesKey.setKey(key, (short) 0);
        // aes key - 256
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        key = new byte[32];
        Util.arrayFillNonAtomic(key, (short) 0, (short) key.length, (byte) 7);
        aesKey.setKey(key, (short) 0);
    }
}
