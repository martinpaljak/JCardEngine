// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.JCSystem;
import javacard.security.*;
import org.bouncycastle.util.Arrays;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * Test for <code>KeyAgreementImpl</code>
 * Test data from NXP JCOP31-36 JavaCard
 */
public class KeyAgreementImplTest extends SimulatorCoreTest {

    /**
     * SelfTest of generateSecret method with ECDH algorithm,
     * of class KeyAgreementImpl.
     */
    @Test
    public void testGenerateSecretECDH() {
        System.out.println("test ecdh");
        testGenerateSecret(KeyPair.ALG_EC_F2M, KeyBuilder.LENGTH_EC_F2M_113, KeyAgreement.ALG_EC_SVDP_DH);
        testGenerateSecret(KeyPair.ALG_EC_F2M, KeyBuilder.LENGTH_EC_F2M_113, KeyAgreement.ALG_EC_SVDP_DH_PLAIN);
        testGenerateSecret(KeyPair.ALG_EC_F2M, KeyBuilder.LENGTH_EC_F2M_113, KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY);
        testGenerateSecret(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_112, KeyAgreement.ALG_EC_SVDP_DH);
        testGenerateSecret(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_112, KeyAgreement.ALG_EC_SVDP_DH_PLAIN);
        testGenerateSecret(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_112, KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY);
        System.out.println("test ecdhc");
        testGenerateSecret(KeyPair.ALG_EC_F2M, KeyBuilder.LENGTH_EC_F2M_113, KeyAgreement.ALG_EC_SVDP_DHC);
        testGenerateSecret(KeyPair.ALG_EC_F2M, KeyBuilder.LENGTH_EC_F2M_113, KeyAgreement.ALG_EC_SVDP_DHC_PLAIN);
        testGenerateSecret(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_112, KeyAgreement.ALG_EC_SVDP_DHC);
        testGenerateSecret(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_112, KeyAgreement.ALG_EC_SVDP_DHC_PLAIN);
        System.out.println("test ecgm");
        testGenerateSecret(KeyPair.ALG_EC_F2M, KeyBuilder.LENGTH_EC_F2M_113, KeyAgreement.ALG_EC_PACE_GM);
        testGenerateSecret(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_112, KeyAgreement.ALG_EC_PACE_GM);
    }

    /**
     * SelfTest of generateSecret method with DH algorithm,
     * of class KeyAgreementImpl.
     */
    @Test
    public void testGenerateSecretDH() {
        System.out.println("test dh");
        generateSecretDH(KeyPair.ALG_DH, KeyBuilder.LENGTH_DH_1024, KeyAgreement.ALG_DH_PLAIN);
        generateSecretDH(KeyPair.ALG_DH, KeyBuilder.LENGTH_DH_2048, KeyAgreement.ALG_DH_PLAIN);
    }

    /**
     * DH method generateSecret
     *
     * @param keyAlg          - key generation algorithm
     * @param keySize         - key size
     * @param keyAgreementAlg - key agreement algorithm
     */
    private void generateSecretDH(byte keyAlg, short keySize, byte keyAgreementAlg) {
        // generate keys
        KeyPair kp = new KeyPair(keyAlg, keySize);
        kp.genKeyPair();
        PrivateKey privateKey1 = kp.getPrivate();
        DHPublicKey publicKey1 = (DHPublicKey) kp.getPublic();
        kp.genKeyPair();
        PrivateKey privateKey2 = kp.getPrivate();
        DHPublicKey publicKey2 = (DHPublicKey) kp.getPublic();
        // generate first secret
        KeyAgreement ka = KeyAgreement.getInstance(keyAgreementAlg, false);
        byte[] secret1 = new byte[256];
        byte[] public2 = new byte[256];
        short publicKeyLength = publicKey2.getY(public2, (short) 0);
        ka.init(privateKey1);
        short secret1Size = ka.generateSecret(public2, (short) 0, publicKeyLength, secret1, (short) 0);
        // generate second secret
        byte[] secret2 = new byte[256];
        byte[] public1 = new byte[256];
        publicKeyLength = publicKey1.getY(public1, (short) 0);
        ka.init(privateKey2);
        short secret2Size = ka.generateSecret(public1, (short) 0, publicKeyLength, secret2, (short) 0);

        // check match of values
        assertEquals(secret1, secret2);
        // DH secret is always prime-length; leading zero bytes are not stripped
        assertEquals(secret1Size, keySize / 8);
        assertEquals(secret2Size, keySize / 8);
    }

    // A shared-domain key's clearKey() clears only its own secret; clearing the shared domain object instead cascades to every sibling key.
    @Test
    public void testSharedDomainECDH() {
        // P-256 domain shared across both key pairs
        Key sharedDomain = KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PARAMETERS, JCSystem.MEMORY_TYPE_PERSISTENT, KeyBuilder.LENGTH_EC_FP_256, false);
        byte mem = JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT;

        ECPublicKey pubA = (ECPublicKey) KeyBuilder.buildKeyWithSharedDomain(KeyBuilder.ALG_TYPE_EC_FP_PUBLIC, mem, sharedDomain, false);
        ECPrivateKey privA = (ECPrivateKey) KeyBuilder.buildKeyWithSharedDomain(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE, mem, sharedDomain, false);
        new KeyPair(pubA, privA).genKeyPair();
        ECPublicKey pubB = (ECPublicKey) KeyBuilder.buildKeyWithSharedDomain(KeyBuilder.ALG_TYPE_EC_FP_PUBLIC, mem, sharedDomain, false);
        ECPrivateKey privB = (ECPrivateKey) KeyBuilder.buildKeyWithSharedDomain(KeyBuilder.ALG_TYPE_EC_FP_PRIVATE, mem, sharedDomain, false);
        new KeyPair(pubB, privB).genKeyPair();

        byte[] secret = ecdh(privA, pubB);
        assertEquals(secret, ecdh(privB, pubA));

        privB.clearKey();
        assertFalse(privB.isInitialized());
        // shared domain survives clearKey(); privA still produces the same secret
        assertTrue(privA.isInitialized());
        assertEquals(secret, ecdh(privA, pubB));

        // clearing the shared domain object itself cascades: every sibling key loses its parameters
        sharedDomain.clearKey();
        assertFalse(privA.isInitialized());
    }

    private static byte[] ecdh(ECPrivateKey priv, ECPublicKey pub) {
        KeyAgreement ka = KeyAgreement.getInstance(KeyAgreement.ALG_EC_SVDP_DH_PLAIN, false);
        ka.init(priv);
        byte[] w = new byte[128];
        short wlen = pub.getW(w, (short) 0);
        byte[] secret = new byte[65];
        short slen = ka.generateSecret(w, (short) 0, wlen, secret, (short) 0);
        return Arrays.copyOf(secret, slen);
    }

    /**
     * Base method generateSecret
     *
     * @param keyAlg          - key generation algorithm
     * @param keySize         - key size
     * @param keyAgreementAlg - key agreement algorithm
     */
    private void testGenerateSecret(byte keyAlg, short keySize, byte keyAgreementAlg) {
        // generate keys
        KeyPair kp = new KeyPair(keyAlg, keySize);
        kp.genKeyPair();
        PrivateKey privateKey1 = kp.getPrivate();
        ECPublicKey publicKey1 = (ECPublicKey) kp.getPublic();
        kp.genKeyPair();
        PrivateKey privateKey2 = kp.getPrivate();
        ECPublicKey publicKey2 = (ECPublicKey) kp.getPublic();
        // generate first secret
        KeyAgreement ka = KeyAgreement.getInstance(keyAgreementAlg, false);
        byte[] secret1 = new byte[65];
        byte[] public2 = new byte[128];
        short publicKeyLength = publicKey2.getW(public2, (short) 0);
        ka.init(privateKey1);
        short secret1Size = ka.generateSecret(public2, (short) 0, publicKeyLength, secret1, (short) 0);
        // generate second secret
        byte[] secret2 = new byte[65];
        byte[] public1 = new byte[128];
        publicKeyLength = publicKey1.getW(public1, (short) 0);
        ka.init(privateKey2);
        short secret2Size = ka.generateSecret(public1, (short) 0, publicKeyLength, secret2, (short) 0);

        // check expected length
        switch (keyAgreementAlg) {
            case KeyAgreement.ALG_EC_SVDP_DH: // no break
            case KeyAgreement.ALG_EC_SVDP_DHC:
                // sha1 size = 20
                assertEquals((int) secret1Size, 20);
                assertEquals((int) secret2Size, 20);
                break;
            case KeyAgreement.ALG_EC_SVDP_DHC_PLAIN: // no break
            case KeyAgreement.ALG_EC_SVDP_DH_PLAIN:
                // round up bit size of key to whole bytes
                assertEquals((int) secret1Size, (int) Math.ceil(keySize / 8.0));
                assertEquals((int) secret2Size, (int) Math.ceil(keySize / 8.0));
                break;
            case KeyAgreement.ALG_EC_SVDP_DH_PLAIN_XY: // no break
            case KeyAgreement.ALG_EC_PACE_GM:
                int fieldSize = (int) Math.ceil(keySize / 8.0);
                assertEquals((int) secret1Size, 1 + fieldSize + fieldSize);
                assertEquals((int) secret2Size, 1 + fieldSize + fieldSize);
                break;
            default:
                fail("unsupported algorithm: " + keyAgreementAlg);
        }

        // check match of values
        assertEquals(secret1, secret2);
    }
}