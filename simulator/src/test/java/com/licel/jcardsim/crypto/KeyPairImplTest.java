// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.Util;
import javacard.security.*;
import org.testng.SkipException;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Test for <code>KeyPairImpl</code>
 */
public class KeyPairImplTest extends SimulatorCoreTest {

    static final short[] RSA_SIZES = new short[]{
            KeyBuilder.LENGTH_RSA_512,
            KeyBuilder.LENGTH_RSA_736,
            KeyBuilder.LENGTH_RSA_768,
            KeyBuilder.LENGTH_RSA_896,
            KeyBuilder.LENGTH_RSA_1024,
            KeyBuilder.LENGTH_RSA_1280,
            KeyBuilder.LENGTH_RSA_1536,
            KeyBuilder.LENGTH_RSA_1984,
            KeyBuilder.LENGTH_RSA_2048,
            KeyBuilder.LENGTH_RSA_3072,
            KeyBuilder.LENGTH_RSA_4096
    };
    static final short[] ECF2M_SIZES = new short[]{
            KeyBuilder.LENGTH_EC_F2M_113,
            KeyBuilder.LENGTH_EC_F2M_131,
            KeyBuilder.LENGTH_EC_F2M_163,
            KeyBuilder.LENGTH_EC_F2M_193
    };
    static final short[] ECFP_SIZES = new short[]{
            KeyBuilder.LENGTH_EC_FP_112,
            KeyBuilder.LENGTH_EC_FP_128,
            KeyBuilder.LENGTH_EC_FP_160,
            KeyBuilder.LENGTH_EC_FP_192,
            KeyBuilder.LENGTH_EC_FP_256,
            KeyBuilder.LENGTH_EC_FP_384,
            KeyBuilder.LENGTH_EC_FP_521
    };
    static final short[] DSA_SIZES = new short[]{
            KeyBuilder.LENGTH_DSA_512,
            KeyBuilder.LENGTH_DSA_768,
            KeyBuilder.LENGTH_DSA_1024
    };
    static final short[] DH_SIZES = new short[]{
            KeyBuilder.LENGTH_DH_1024,
            DHKeyImpl.LENGTH_DH_1536,
            KeyBuilder.LENGTH_DH_2048
    };

    @Test
    public void testConstructor() {
        if (!"true".equals(System.getProperty("slow.tests"))) {
            throw new SkipException("slow.tests not enabled");
        }
        testConstructorRSA(KeyPair.ALG_RSA);
        testConstructorRSA(KeyPair.ALG_RSA_CRT);
    }

    /**
     * Test of constructor RSA/RSA_CRT
     */
    private void testConstructorRSA(byte algo) {
        KeyPair instance = null;
        byte[] expBuf = new byte[3];
        byte[] customExp = new byte[]{0x03};
        for (int i = 0; i < RSA_SIZES.length; i++) {
            instance = new KeyPair(algo, RSA_SIZES[i]);
            // https://github.com/licel/jcardsim/issues/42
            PublicKey publicKey = instance.getPublic();
            assertNotNull(publicKey);
            assertTrue(publicKey instanceof RSAPublicKey);
            ((RSAPublicKey) publicKey).setExponent(customExp, (short) 0, (short) customExp.length);
            instance.genKeyPair();
            short expSize = ((RSAPublicKey) publicKey).getExponent(expBuf, (short) 0);
            assertEquals((int) expSize, customExp.length);
            assertEquals(Util.arrayCompare(expBuf, (short) 0, customExp, (short) 0, expSize), 0);
        }
    }

    /**
     * Test of genKeyPair method, of class KeyPairImpl.
     * algorithm RSA - NXP JCOP not support this algorithm
     * for on-card key generation
     */
    @Test
    public void testGenKeyPairRSA() {
        if (!"true".equals(System.getProperty("slow.tests"))) {
            throw new SkipException("slow.tests not enabled");
        }
        KeyPairImpl instance = null;
        short offset = 10;
        byte[] publicExponent = new byte[3];
        byte[] publicExponentArray = new byte[offset + 3];
        byte[] etalonExponent = new byte[]{(byte) 0x01, (byte) 0x00, (byte) 0x01};
        for (int i = 0; i < RSA_SIZES.length; i++) {
            instance = new KeyPairImpl(KeyPair.ALG_RSA, RSA_SIZES[i]);
            instance.genKeyPair();
            PublicKey publicKey = instance.getPublic();
            assertTrue(publicKey instanceof RSAPublicKey);
            // https://code.google.com/p/jcardsim/issues/detail?id=14
            short publicExponentSize = ((RSAPublicKey) publicKey).getExponent(publicExponentArray, offset);
            assertEquals((int) publicExponentSize, etalonExponent.length);
            ((RSAPublicKey) publicKey).getExponent(publicExponent, (short) 0);
            assertEquals(publicExponent, etalonExponent);
            PrivateKey privateKey = instance.getPrivate();
            assertTrue(privateKey instanceof RSAPrivateKey);
        }
    }

    /**
     * Test of genKeyPair method, of class KeyPairImpl.
     * algorithm RSA - NXP JCOP not support this algorithm
     * for on-card key generation
     */
    @Test
    public void testGenKeyPairRSAWithCustomPublicExponent() {
        byte[] customExponent = new byte[]{(byte) 0x03};
        RSAPublicKey publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        KeyPair instance = new KeyPair(publicKey, null);
        publicKey.setExponent(customExponent, (short) 0, (short) customExponent.length);
        instance.genKeyPair();
        publicKey = (RSAPublicKey) instance.getPublic();
        byte[] generatedExponent = new byte[customExponent.length];
        publicKey.getExponent(generatedExponent, (short) 0);
        assertEquals(generatedExponent, customExponent);
        // public exponent is capped at 32 bits; a 5-byte value is rejected
        byte[] tooWide = new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05};
        RSAPublicKey wideKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        assertThrows(CryptoException.class, () -> wideKey.setExponent(tooWide, (short) 0, (short) tooWide.length));
    }

    /**
     * Test of genKeyPair method, of class KeyPairImpl.
     * algorithm EC - NXP JCOP not support this algorithm
     * for on-card key generation
     */
    @Test
    public void testGenKeyPairECWithCustomDomainParameters() {
        KeyPair instance = new KeyPair(KeyPair.ALG_EC_F2M, KeyBuilder.LENGTH_EC_F2M_193);
        instance.genKeyPair();
        ECPublicKey ecPublicKey = (ECPublicKey) instance.getPublic();
        KeyPair instance1 = new KeyPair(ecPublicKey, null);
        instance1.genKeyPair();
        ECPublicKey ecPublicKey1 = (ECPublicKey) instance1.getPublic();
        byte[] a = new byte[266];
        byte[] a1 = new byte[266];
        ecPublicKey.getA(a, (short) 0);
        ecPublicKey1.getA(a1, (short) 0);
        assertEquals(a, a1);
    }

    /**
     * Test of genKeyPair method, of class KeyPairImpl.
     * algorithm RSA CRT - NXP JCOP support only this algorithm
     * for on-card key generation
     */
    @Test
    public void testGenKeyPairRSACrt() {
        if (!"true".equals(System.getProperty("slow.tests"))) {
            throw new SkipException("slow.tests not enabled");
        }
        KeyPairImpl instance = null;
        for (int i = 0; i < RSA_SIZES.length; i++) {
            instance = new KeyPairImpl(KeyPair.ALG_RSA_CRT, RSA_SIZES[i]);
            instance.genKeyPair();
            PublicKey publicKey = instance.getPublic();
            assertTrue(publicKey instanceof RSAPublicKey);
            PrivateKey privateKey = instance.getPrivate();
            assertTrue(privateKey instanceof RSAPrivateCrtKey);
        }
    }

    /**
     * Test of genKeyPair method, of class KeyPairImpl.
     * algorithm EC_F2M - NXP JCOP support only this algorithm
     * for on-card key generation
     */
    @Test
    public void testGenKeyPairECF2M() {
        KeyPairImpl instance = null;
        for (int i = 0; i < ECF2M_SIZES.length; i++) {
            instance = new KeyPairImpl(KeyPair.ALG_EC_F2M, ECF2M_SIZES[i]);
            instance.genKeyPair();
            PublicKey publicKey = instance.getPublic();
            assertTrue(publicKey instanceof ECPublicKey);
            PrivateKey privateKey = instance.getPrivate();
            assertTrue(privateKey instanceof ECPrivateKey);
        }
    }

    /**
     * Test of genKeyPair method, of class KeyPairImpl.
     * algorithm EC_FP - NXP JCOP  not support  this algorithm
     * for on-card key generation
     */
    @Test
    public void testGenKeyPairECFP() {
        KeyPairImpl instance = null;
        for (int i = 0; i < ECFP_SIZES.length; i++) {
            instance = new KeyPairImpl(KeyPair.ALG_EC_FP, ECFP_SIZES[i]);
            instance.genKeyPair();
            PublicKey publicKey = instance.getPublic();
            assertTrue(publicKey instanceof ECPublicKey);
            PrivateKey privateKey = instance.getPrivate();
            assertTrue(privateKey instanceof ECPrivateKey);
        }
    }

    /**
     * Test of genKeyPair method, of class KeyPairImpl.
     * algorithm DSA - NXP JCOP  not support  this algorithm
     * for on-card key generation
     */
    @Test
    public void testGenKeyPairDSA() {
        KeyPairImpl instance = null;
        for (int i = 0; i < DSA_SIZES.length; i++) {
            instance = new KeyPairImpl(KeyPair.ALG_DSA, DSA_SIZES[i]);
            instance.genKeyPair();
            PublicKey publicKey = instance.getPublic();
            assertTrue(publicKey instanceof DSAPublicKey);
            PrivateKey privateKey = instance.getPrivate();
            assertTrue(privateKey instanceof DSAPrivateKey);
        }
    }

    /**
     * Test of genKeyPair method, of class KeyPairImpl.
     * algorithm DH
     */
    @Test
    public void testGenKeyPairDH() {
        KeyPairImpl instance = null;
        for (int i = 0; i < DH_SIZES.length; i++) {
            instance = new KeyPairImpl(KeyPair.ALG_DH, DH_SIZES[i]);
            instance.genKeyPair();
            PublicKey publicKey = instance.getPublic();
            assertTrue(publicKey instanceof DHPublicKey);
            PrivateKey privateKey = instance.getPrivate();
            assertTrue(privateKey instanceof DHPrivateKey);
        }
    }
}
