// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import org.bouncycastle.util.Arrays;
import org.testng.SkipException;
import org.testng.annotations.Test;

import java.util.Random;

import static org.testng.Assert.*;

/**
 * Test for <code>AsymmetricCipherImpl</code>
 * Test data from NXP JCOP31-36 JavaCard
 */
public class AsymmetricCipherImplTest extends SimulatorCoreTest {

    /**
     * SelfTest of RSA Encryption/Decryption, of class AsymmetricCipherImpl.
     */
    @Test
    public void testSelftRSA_NOPAD() {
        if (!"true".equals(System.getProperty("slow.tests"))) {
            throw new SkipException("slow.tests not enabled");
        }
        // Refer to https://docs.oracle.com/javacard/3.0.5/api/javacardx/crypto/Cipher.html#ALG_RSA_NOPAD
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512, (short) ((KeyBuilder.LENGTH_RSA_512 / Byte.SIZE)));
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_736, (short) ((KeyBuilder.LENGTH_RSA_736 / Byte.SIZE)));
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_768, (short) ((KeyBuilder.LENGTH_RSA_768 / Byte.SIZE)));
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_896, (short) ((KeyBuilder.LENGTH_RSA_896 / Byte.SIZE)));
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024, (short) ((KeyBuilder.LENGTH_RSA_1024 / Byte.SIZE)));
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1280, (short) ((KeyBuilder.LENGTH_RSA_1280 / Byte.SIZE)));
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1536, (short) ((KeyBuilder.LENGTH_RSA_1536 / Byte.SIZE)));
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1984, (short) ((KeyBuilder.LENGTH_RSA_1984 / Byte.SIZE)));
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048, (short) ((KeyBuilder.LENGTH_RSA_2048 / Byte.SIZE)));
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_3072, (short) ((KeyBuilder.LENGTH_RSA_3072 / Byte.SIZE)));
        testSelftRSA_NOPAD(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_4096, (short) ((KeyBuilder.LENGTH_RSA_4096 / Byte.SIZE)));

        try {
            short messageLen = (short) ((KeyBuilder.LENGTH_RSA_512 / Byte.SIZE));
            byte[] msgEqualOrGreaterThanRsaModulus = new byte[messageLen];
            Arrays.fill(msgEqualOrGreaterThanRsaModulus, (byte) 0xFF);
            testSelftRSA(Cipher.ALG_RSA_NOPAD, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512, messageLen, msgEqualOrGreaterThanRsaModulus);
            assert false;
        } catch (CryptoException ex) {
            assertEquals(ex.getReason(), CryptoException.ILLEGAL_USE);
        }
    }

    private void testSelftRSA_NOPAD(byte algorithm, byte keyPairAlgorithm, short keySizeInBits, short messageLen) {
        byte[] msg = new byte[messageLen];
        new Random().nextBytes(msg);
        msg[0] = (byte) 0x01; // Ensure that message is not greater than RSA modulus

        testSelftRSA(algorithm, keyPairAlgorithm, keySizeInBits, messageLen, msg);
    }

    @Test
    public void testSelftRSA_PKCS1() {
        if (!"true".equals(System.getProperty("slow.tests"))) {
            throw new SkipException("slow.tests not enabled");
        }
        // Refer to https://www.rfc-editor.org/rfc/rfc8017#section-7.2.1 and https://docs.oracle.com/javacard/3.0.5/api/javacardx/crypto/Cipher.html#ALG_RSA_PKCS1
        // mLen <= k - 11, k is the length in octets of the modulus n

        // Test at maximum message length, mLen = k - 11
        // RSA Key Pair
        short k = KeyBuilder.LENGTH_RSA_512 / Byte.SIZE;
        short maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_736 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_736, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_768 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_768, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_896 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_896, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1024 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1280 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1280, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1536 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1536, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1984 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1984, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_2048 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_3072 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_3072, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_4096 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_4096, maxMsgLen);

        // RSA Key Pair with private key in its Chinese Remainder Theorem form
        k = KeyBuilder.LENGTH_RSA_512 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_736 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_736, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_768 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_768, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_896 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_896, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1024 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1280 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1280, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1536 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1536, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1984 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1984, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_2048 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_3072 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_3072, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_4096 / Byte.SIZE;
        maxMsgLen = (short) (k - 11);
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_4096, maxMsgLen);

        // Test with mLen < k - 11
        testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_4096, (short) (maxMsgLen - 1));

        // Test with mLen > k - 11
        try {
            testSelftRSA(Cipher.ALG_RSA_PKCS1, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_4096, (short) (maxMsgLen + 1));
            assert false;
        } catch (CryptoException ex) {
            assertEquals(ex.getReason(), CryptoException.ILLEGAL_USE);
        }
    }

    @Test
    public void testSelftRSA_PKCS1_OEAP() {
        if (!"true".equals(System.getProperty("slow.tests"))) {
            throw new SkipException("slow.tests not enabled");
        }
        // Refer to https://www.rfc-editor.org/rfc/rfc8017#section-7.1.1
        // mLen <= k - 2hLen - 2,
        //      k is the length in octets of the modulus n and
        //      hLen is the hash function output octet length, SHA1 is used as default https://www.rfc-editor.org/rfc/rfc8017#appendix-A.2.1
        short hLen = 20; // SHA1 hash size is 20 bytes

        // Test at maximum message length, mLen = k - 2hLen - 2
        // RSA Key Pair
        short k = KeyBuilder.LENGTH_RSA_512 / Byte.SIZE;
        short maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_512, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_736 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_736, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_768 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_768, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_896 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_896, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1024 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1024, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1280 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1280, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1536 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1536, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1984 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_1984, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_2048 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_3072 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_3072, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_4096 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_4096, maxMsgLen);

        // RSA Key Pair with private key in its Chinese Remainder Theorem form
        k = KeyBuilder.LENGTH_RSA_512 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_512, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_736 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_736, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_768 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_768, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_896 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_896, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1024 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1280 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1280, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1536 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1536, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_1984 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1984, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_2048 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_3072 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_3072, maxMsgLen);

        k = KeyBuilder.LENGTH_RSA_4096 / Byte.SIZE;
        maxMsgLen = (short) (k - (2 * hLen) - 2);
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_4096, maxMsgLen);

        // Test with mLen < k - 2hLen - 2
        testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_4096, (short) (maxMsgLen - 1));

        // Test with mLen > k - 2hLen - 2
        try {
            testSelftRSA(Cipher.ALG_RSA_PKCS1_OAEP, KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_4096, (short) (maxMsgLen + 1));
            assert false;
        } catch (CryptoException ex) {
            assertEquals(ex.getReason(), CryptoException.ILLEGAL_USE);
        }
    }

    private void testSelftRSA(byte algorithm, byte keyPairAlgorithm, short keySizeInBits, short messageLen) {
        byte[] msg = new byte[messageLen];
        new Random().nextBytes(msg);
        testSelftRSA(algorithm, keyPairAlgorithm, keySizeInBits, messageLen, msg);
    }

    private void testSelftRSA(byte algorithm, byte keyPairAlgorithm, short keySizeInBits, short messageLen, byte[] msg) {
        Cipher cipher = Cipher.getInstance(algorithm, false);
        KeyPair kp = new KeyPair(keyPairAlgorithm, keySizeInBits);
        kp.genKeyPair();

        cipher.init(kp.getPublic(), Cipher.MODE_ENCRYPT);

        short keySizeInBytes = (short) (keySizeInBits / Byte.SIZE);
        byte[] encryptedMsg = new byte[keySizeInBytes];

        cipher.doFinal(msg, (short) 0, messageLen, encryptedMsg, (short) 0);

        cipher.init(kp.getPrivate(), Cipher.MODE_DECRYPT);
        byte[] decryptedMsg = new byte[messageLen];
        cipher.doFinal(encryptedMsg, (short) 0, (short) encryptedMsg.length, decryptedMsg, (short) 0);

        assertEquals(decryptedMsg, msg);
    }

    @Test
    public void testOAEP_SHA256_RoundTripAndAccessors() {
        Cipher cipher = Cipher.getInstance(Cipher.CIPHER_RSA, Cipher.PAD_PKCS1_OAEP_SHA256, false);
        KeyPair kp = new KeyPair(KeyPair.ALG_RSA, KeyBuilder.LENGTH_RSA_2048);
        kp.genKeyPair();

        byte[] msg = new byte[16];
        new Random().nextBytes(msg);

        cipher.init(kp.getPublic(), Cipher.MODE_ENCRYPT);
        byte[] encrypted = new byte[KeyBuilder.LENGTH_RSA_2048 / Byte.SIZE];
        cipher.doFinal(msg, (short) 0, (short) msg.length, encrypted, (short) 0);

        cipher.init(kp.getPrivate(), Cipher.MODE_DECRYPT);
        byte[] decrypted = new byte[msg.length];
        cipher.doFinal(encrypted, (short) 0, (short) encrypted.length, decrypted, (short) 0);

        // OAEP-SHA256 round-trip recovers the original plaintext
        assertEquals(decrypted, msg);
        // accessors report the requested (cipher, padding) pair
        assertEquals(cipher.getCipherAlgorithm(), Cipher.CIPHER_RSA);
        assertEquals(cipher.getPaddingAlgorithm(), Cipher.PAD_PKCS1_OAEP_SHA256);

        try {
            Cipher.getInstance(Cipher.CIPHER_RSA, Cipher.PAD_NULL, false);
            assert false;
        } catch (CryptoException ex) {
            // unrecognised RSA padding is rejected with NO_SUCH_ALGORITHM
            assertEquals(ex.getReason(), CryptoException.NO_SUCH_ALGORITHM);
        }
    }

    @Test
    public void testRegression_CipherDoFinal_bufferPosNotReset() throws Exception {
        Cipher encryptEngine = Cipher.getInstance(Cipher.ALG_RSA_PKCS1, false);
        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_1024);
        keyPair.genKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        encryptEngine.init(publicKey, Cipher.MODE_ENCRYPT);

        byte[] buffer = new byte[256];
        encryptEngine.doFinal(buffer, (short) 0, (short) 59, buffer, (short) 0);
        try {
            encryptEngine.doFinal(buffer, (short) 0, (short) 59, buffer, (short) 0);
        } catch (CryptoException e) {
            // For RSA1024, data len into PKCS1 frame is 117B, but because AssymetricCipherImpl.bufferPos is not set
            // to 0 during doFinal(), it will emit exception because 68 + 68 > 117
            assert false;
        }
    }
}
