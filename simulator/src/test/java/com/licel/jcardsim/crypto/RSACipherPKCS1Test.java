// SPDX-FileCopyrightText: 2013 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.framework.Util;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import org.bouncycastle.util.encoders.Hex;

/**
 * Test for <code>AsymmetricCipherImpl</code> and <code>ALG_RSA_PKCS1</code> algorithm implementation.
 */
public class RSACipherPKCS1Test extends SimulatorCoreTest {

    // RSA keypair data
    private static final byte[] rsaPrivateKeyModulus = Hex.decode("bedfd37a08e29a5827542a4918cee41a60dc6275bdb08d15a365e67ba9dc09115f9fbf29e6c282c8356b0f109b1962fdbd964921e4220808806cd1dea6d3c38f");

    private static final byte[] rsaPrivateKeyExponent = Hex.decode("8421fe0ba4caf97dbcfc0ea9bb7abd7d65402b08c6dfc94b096a293bc242882344af08824cff42a4b8d2dacceec534ed7101ab3b76de6ca2cb7c38b69a4b2801");

    private static final byte[] rsaPublicKeyExponent = {
            (byte) 0x01, (byte) 0x00, (byte) 0x01};

    /**
     * SelfTest of RSA Encryption/Decryption, of class AsymmetricCipherImpl and ALG_RSA_PKCS1 algorithm implementation.
     */
    @SuppressWarnings("deprecation") // ALG_PSEUDO_RANDOM
    @Test
    public void testRSAPKCS1() {
        Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);

        RSAPrivateKey privateKey = (RSAPrivateKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PRIVATE, KeyBuilder.LENGTH_RSA_512, false);
        RSAPublicKey publicKey = (RSAPublicKey) KeyBuilder.buildKey(KeyBuilder.TYPE_RSA_PUBLIC, KeyBuilder.LENGTH_RSA_512, false);

        privateKey.setExponent(rsaPrivateKeyExponent, (short) 0, (short) rsaPrivateKeyExponent.length);
        privateKey.setModulus(rsaPrivateKeyModulus, (short) 0, (short) rsaPrivateKeyModulus.length);
        publicKey.setExponent(rsaPublicKeyExponent, (short) 0, (short) rsaPublicKeyExponent.length);
        publicKey.setModulus(rsaPrivateKeyModulus, (short) 0, (short) rsaPrivateKeyModulus.length);

        cipher.init(publicKey, Cipher.MODE_ENCRYPT);
        byte[] msg = new byte[23];
        byte[] encryptedMsg = new byte[64];
        RandomData rnd = RandomData.getInstance(RandomData.ALG_PSEUDO_RANDOM);
        rnd.generateData(msg, (short) 0, (short) msg.length);
        cipher.doFinal(msg, (short) 0, (short) msg.length, encryptedMsg, (short) 0);

        cipher.init(privateKey, Cipher.MODE_DECRYPT);
        byte[] decryptedMsg = new byte[64];
        short decryptedMsgLen = cipher.doFinal(encryptedMsg, (short) 0, (short) encryptedMsg.length, decryptedMsg, (short) 0);
        assertEquals(msg.length, decryptedMsgLen);
        assertEquals(0, Util.arrayCompare(msg, (short) 0, decryptedMsg, (short) 0, decryptedMsgLen));
    }
}
