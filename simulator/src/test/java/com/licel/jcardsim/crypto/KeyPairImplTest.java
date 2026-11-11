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
        for (byte type : new byte[]{KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.TYPE_RSA_CRT_PRIVATE}) {
            for (short size : new short[]{-1, KeyBuilder.LENGTH_RSA_512 - 1, KeyBuilder.LENGTH_RSA_4096 + 1}) {
                assertEquals(expectThrows(CryptoException.class, () -> KeyBuilder.buildKey(type, size, false)).getReason(), CryptoException.NO_SUCH_ALGORITHM);
            }
        }
        // FIPS 186-2 4 and RFC 2631 2.2 set a 512-bit minimum for p
        for (byte type : new byte[]{KeyBuilder.TYPE_DSA_PUBLIC, KeyBuilder.TYPE_DSA_PRIVATE, KeyBuilder.TYPE_DH_PUBLIC, KeyBuilder.TYPE_DH_PRIVATE}) {
            for (short size : new short[]{-1, 511}) {
                assertEquals(expectThrows(CryptoException.class, () -> KeyBuilder.buildKey(type, size, false)).getReason(), CryptoException.NO_SUCH_ALGORITHM);
            }
        }
        for (byte type : new byte[]{KeyBuilder.TYPE_HMAC, KeyBuilder.TYPE_EC_FP_PUBLIC}) {
            for (short size : new short[]{-16, 0}) {
                assertEquals(expectThrows(CryptoException.class, () -> KeyBuilder.buildKey(type, size, false)).getReason(), CryptoException.NO_SUCH_ALGORITHM);
            }
        }
        for (byte exponent : new byte[]{0, 1, 4}) {
            var pair = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512);
            ((RSAPublicKey) pair.getPublic()).setExponent(new byte[]{exponent}, (short) 0, (short) 1);
            assertEquals(expectThrows(CryptoException.class, pair::genKeyPair).getReason(), CryptoException.NO_SUCH_ALGORITHM);
        }
        var ec = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        var composite = new byte[32];
        composite[31] = 4;
        var ecpub = (ECPublicKey) ec.getPublic();
        ecpub.setFieldFP(composite, (short) 0, (short) 32);
        ecpub.setA(composite, (short) 0, (short) 32);
        ecpub.setB(composite, (short) 0, (short) 32);
        ecpub.setR(composite, (short) 0, (short) 32);
        var point = new byte[65];
        point[0] = 4;
        ecpub.setG(point, (short) 0, (short) 65);
        assertEquals(expectThrows(CryptoException.class, ec::genKeyPair).getReason(), CryptoException.NO_SUCH_ALGORITHM);
        byte[] customExponent = new byte[]{(byte) 0x03};
        RSAPublicKey publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        KeyPair instance = new KeyPair(publicKey, null);
        publicKey.setExponent(customExponent, (short) 0, (short) customExponent.length);
        instance.genKeyPair();
        publicKey = (RSAPublicKey) instance.getPublic();
        byte[] generatedExponent = new byte[customExponent.length];
        publicKey.getExponent(generatedExponent, (short) 0);
        assertEquals(generatedExponent, customExponent);
        RSAPublicKey wideKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        // an exponent wider than 4 bytes is accepted and read back at its own length
        byte[] wideExponent = new byte[]{(byte) 0x01, 0, 0, 0, 0, 0, 0, (byte) 0x01};
        wideKey.setExponent(wideExponent, (short) 0, (short) wideExponent.length);
        byte[] readBack = new byte[wideExponent.length];
        assertEquals(wideKey.getExponent(readBack, (short) 0), (short) wideExponent.length);
        assertEquals(readBack, wideExponent);
        // an exponent wider than the modulus cannot satisfy e < n and is rejected
        byte[] tooWide = new byte[(KeyBuilder.LENGTH_RSA_1024 / 8) + 1];
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
        // 1001 bits round up to 126 bytes
        var dsa = (DSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DSA_PUBLIC, (short) 1001, false);
        var prime = bigEndian(126);
        dsa.setP(prime, (short) 0, (short) prime.length);
        assertEquals(dsa.getP(new byte[126], (short) 0), 126);
        // JC 3.2 KeyPair.genKeyPair: default parameter sets MAY be used
        var custom = new KeyPairImpl(KeyPair.ALG_DSA, (short) 576);
        assertEquals(expectThrows(CryptoException.class, custom::genKeyPair).getReason(), CryptoException.ILLEGAL_VALUE);
    }

    private static byte[] bigEndian(int bytes) {
        var value = new byte[bytes];
        value[0] = 0x7F;
        value[bytes - 1] = 1;
        return value;
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
        // 1025 bits round up to 129 bytes
        var dh = (DHPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DH_PUBLIC, (short) 1025, false);
        var prime = bigEndian(129);
        dh.setP(prime, (short) 0, (short) prime.length);
        assertEquals(dh.getP(new byte[129], (short) 0), 129);
    }
}
