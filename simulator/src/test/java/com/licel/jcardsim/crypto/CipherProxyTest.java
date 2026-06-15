// SPDX-FileCopyrightText: 2022 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.security.AESKey;
import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;
import org.bouncycastle.util.encoders.Hex;
import org.junit.jupiter.api.Test;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

public class CipherProxyTest extends SimulatorCoreTest {

    // The deprecated cipher algorithm list is created because JavaCard 3.0.5 API uses only javadoc annotation @deprecated
    // And not use the Java annotation @Deprecated, which can be read by java.lang.reflect.Field
    // https://docs.oracle.com/javacard/3.0.5/api/javacardx/crypto/Cipher.html
    String[] CIPHER_DEPRECATED_ALG_JAVACARD_V3_0_5 = {
        "ALG_AES_BLOCK_192_CBC_NOPAD",
        "ALG_AES_BLOCK_192_ECB_NOPAD",
        "ALG_AES_BLOCK_256_CBC_NOPAD",
        "ALG_AES_BLOCK_256_ECB_NOPAD",
        "ALG_RSA_ISO14888",
        "ALG_RSA_ISO9796",
    };

    @Test
    public void testSupportCipherForJavaCardv3_0_5() throws ClassNotFoundException {
        ArrayList<Field> cipher_alg_fields = new ArrayList<>();

        for(Field field : Class.forName("javacardx.crypto.Cipher").getDeclaredFields()){
            if( field.getName().startsWith("ALG_") ){
                List<String> deprecated_list = Arrays.asList(CIPHER_DEPRECATED_ALG_JAVACARD_V3_0_5);
                if (!deprecated_list.contains(field.getName())) {
                    cipher_alg_fields.add(field);
                }
            }
        }

        for( Field alg_field : cipher_alg_fields ) {
            try {
                Cipher engine = Cipher.getInstance(alg_field.getByte(null), false);
            }
            catch (Throwable ex){
                System.out.println("Cipher algorithm " + alg_field.getName() + " has not been implemented yet!!!");
            }
        }

    }

    @Test
    public void testOneShotAndCipherPaddingResolution() {
        // 3-arg getInstance maps (cipher, padding) pair to the corresponding ALG_* constant
        assertEquals(Cipher.ALG_RSA_NOPAD, Cipher.getInstance(Cipher.CIPHER_RSA, Cipher.PAD_NOPAD, false).getAlgorithm());
        assertEquals(Cipher.ALG_RSA_PKCS1, Cipher.getInstance(Cipher.CIPHER_RSA, Cipher.PAD_PKCS1, false).getAlgorithm());
        assertEquals(Cipher.ALG_RSA_PKCS1_OAEP, Cipher.getInstance(Cipher.CIPHER_RSA, Cipher.PAD_PKCS1_OAEP, false).getAlgorithm());
        assertEquals(Cipher.ALG_DES_CBC_ISO9797_M2, Cipher.getInstance(Cipher.CIPHER_DES_CBC, Cipher.PAD_ISO9797_M2, false).getAlgorithm());
        assertEquals(Cipher.ALG_AES_CBC_ISO9797_M2, Cipher.getInstance(Cipher.CIPHER_AES_CBC, Cipher.PAD_ISO9797_M2, false).getAlgorithm());
        // an unsupported (cipher, padding) combination throws NO_SUCH_ALGORITHM
        try {
            Cipher.getInstance(Cipher.CIPHER_AES_ECB, Cipher.PAD_PKCS5, false);
            fail("No exception");
        } catch (CryptoException e) {
            assertEquals(CryptoException.NO_SUCH_ALGORITHM, e.getReason());
        }

        // Cipher.OneShot: AES-128 ECB encrypt/decrypt round trip; update() must throw ILLEGAL_USE
        AESKey key = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        key.setKey(Hex.decode("000102030405060708090A0B0C0D0E0F"), (short) 0);
        byte[] msg = Hex.decode("00112233445566778899AABBCCDDEEFF");
        byte[] ct = new byte[16];
        byte[] back = new byte[16];

        Cipher.OneShot enc = Cipher.OneShot.open(Cipher.CIPHER_AES_ECB, Cipher.PAD_NOPAD);
        try {
            enc.init(key, Cipher.MODE_ENCRYPT);
            assertEquals(16, enc.doFinal(msg, (short) 0, (short) msg.length, ct, (short) 0));
            try {
                enc.update(msg, (short) 0, (short) msg.length, ct, (short) 0);
                fail("No exception");
            } catch (CryptoException e) {
                assertEquals(CryptoException.ILLEGAL_USE, e.getReason());
            }
        } finally {
            enc.close();
        }
        // after close(), a further call throws ILLEGAL_USE
        try {
            enc.doFinal(msg, (short) 0, (short) msg.length, ct, (short) 0);
            fail("No exception");
        } catch (CryptoException e) {
            assertEquals(CryptoException.ILLEGAL_USE, e.getReason());
        }

        Cipher.OneShot dec = Cipher.OneShot.open(Cipher.CIPHER_AES_ECB, Cipher.PAD_NOPAD);
        try {
            dec.init(key, Cipher.MODE_DECRYPT);
            assertEquals(16, dec.doFinal(ct, (short) 0, (short) ct.length, back, (short) 0));
        } finally {
            dec.close();
        }
        assertTrue(Arrays.equals(msg, back));
    }
}
