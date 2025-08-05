package com.licel.jcardsim.crypto;
/*
 * Copyright 2011 Licel LLC.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.Util;
import javacard.security.*;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

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
            assertInstanceOf(RSAPublicKey.class, publicKey);
            ((RSAPublicKey) publicKey).setExponent(customExp, (short) 0, (short) customExp.length);
            instance.genKeyPair();
            short expSize = ((RSAPublicKey) publicKey).getExponent(expBuf, (short) 0);
            assertEquals(customExp.length, expSize);
            assertEquals(0, Util.arrayCompare(expBuf, (short) 0, customExp, (short) 0, expSize));
        }
    }

    /**
     * Test of genKeyPair method, of class KeyPairImpl.
     * algorithm RSA - NXP JCOP not support this algorithm
     * for on-card key generation
     */
    @Test
    public void testGenKeyPairRSA() {
        KeyPairImpl instance = null;
        short offset = 10;
        byte[] publicExponent = new byte[3];
        byte[] publicExponentArray = new byte[offset + 3];
        byte[] etalonExponent = new byte[]{(byte) 0x01, (byte) 0x00, (byte) 0x01};
        for (int i = 0; i < RSA_SIZES.length; i++) {
            instance = new KeyPairImpl(KeyPair.ALG_RSA, RSA_SIZES[i]);
            instance.genKeyPair();
            PublicKey publicKey = instance.getPublic();
            assertInstanceOf(RSAPublicKey.class, publicKey);
            // https://code.google.com/p/jcardsim/issues/detail?id=14
            short publicExponentSize = ((RSAPublicKey) publicKey).getExponent(publicExponentArray, offset);
            assertEquals(etalonExponent.length, publicExponentSize);
            ((RSAPublicKey) publicKey).getExponent(publicExponent, (short) 0);
            assertArrayEquals(publicExponent, etalonExponent);
            PrivateKey privateKey = instance.getPrivate();
            assertInstanceOf(RSAPrivateKey.class, privateKey);
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
        assertArrayEquals(customExponent, generatedExponent);
        customExponent = new byte[]{(byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04, (byte) 0x05};
        publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_1024, false);
        instance = new KeyPair(publicKey, null);
        publicKey.setExponent(customExponent, (short) 0, (short) customExponent.length);
        instance.genKeyPair();
        publicKey = (RSAPublicKey) instance.getPublic();
        generatedExponent = new byte[customExponent.length];
        publicKey.getExponent(generatedExponent, (short) 0);
        assertArrayEquals(customExponent, generatedExponent);
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
        assertArrayEquals(a, a1);
    }

    /**
     * Test of genKeyPair method, of class KeyPairImpl.
     * algorithm RSA CRT - NXP JCOP support only this algorithm
     * for on-card key generation
     */
    @Test
    public void testGenKeyPairRSACrt() {
        KeyPairImpl instance = null;
        for (int i = 0; i < RSA_SIZES.length; i++) {
            instance = new KeyPairImpl(KeyPair.ALG_RSA_CRT, RSA_SIZES[i]);
            instance.genKeyPair();
            PublicKey publicKey = instance.getPublic();
            assertInstanceOf(RSAPublicKey.class, publicKey);
            PrivateKey privateKey = instance.getPrivate();
            assertInstanceOf(RSAPrivateCrtKey.class, privateKey);
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
            assertInstanceOf(ECPublicKey.class, publicKey);
            PrivateKey privateKey = instance.getPrivate();
            assertInstanceOf(ECPrivateKey.class, privateKey);
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
            assertInstanceOf(ECPublicKey.class, publicKey);
            PrivateKey privateKey = instance.getPrivate();
            assertInstanceOf(ECPrivateKey.class, privateKey);
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
            assertInstanceOf(DSAPublicKey.class, publicKey);
            PrivateKey privateKey = instance.getPrivate();
            assertInstanceOf(DSAPrivateKey.class, privateKey);
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
            assertInstanceOf(DHPublicKey.class, publicKey);
            PrivateKey privateKey = instance.getPrivate();
            assertInstanceOf(DHPrivateKey.class, privateKey);
        }
    }
}
