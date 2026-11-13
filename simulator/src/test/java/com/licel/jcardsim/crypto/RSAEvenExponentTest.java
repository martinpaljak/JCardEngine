// SPDX-FileCopyrightText: 2026 Satochip
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.SimulatorCoreTest;
import javacard.security.KeyPair;
import javacard.security.RSAPublicKey;
import javacardx.crypto.Cipher;
import org.testng.annotations.Test;

import java.math.BigInteger;

import static org.testng.Assert.assertEquals;

/**
 * ALG_RSA_NOPAD with an even public exponent.
 *
 * <p>Java Card places no validity constraints on a raw RSA exponent: ALG_RSA_NOPAD is defined as
 * plain modular exponentiation over a modulus-wide block. JCMathLib and the libraries derived from
 * it rely on this, setting e = 2 so that the card's RSA engine can be used as a fast modular
 * squaring primitive for bignum arithmetic.
 *
 * <p>BouncyCastle, however, rejects an even exponent when the key is presented as a public key, so
 * the operation used to fail with CryptoException.ILLEGAL_USE on a simulator while working on real
 * hardware.
 */
public class RSAEvenExponentTest extends SimulatorCoreTest {

    private static final short KEY_BITS = 768;
    private static final short KEY_BYTES = KEY_BITS / 8;

    @Test
    public void testSquaringWithEvenPublicExponent() {
        KeyPair keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KEY_BITS);
        keyPair.genKeyPair();

        RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
        publicKey.setExponent(new byte[]{0x02}, (short) 0, (short) 1);

        byte[] modulusBytes = new byte[KEY_BYTES];
        short modulusLen = publicKey.getModulus(modulusBytes, (short) 0);
        BigInteger modulus =
            new BigInteger(1, java.util.Arrays.copyOf(modulusBytes, modulusLen));

        // A full modulus-wide input block, as ALG_RSA_NOPAD is specified to take.
        byte[] input = new byte[KEY_BYTES];
        java.util.Arrays.fill(input, (byte) 0x06);
        byte[] output = new byte[KEY_BYTES];

        Cipher cipher = Cipher.getInstance(Cipher.ALG_RSA_NOPAD, false);
        cipher.init(publicKey, Cipher.MODE_ENCRYPT);
        short outLen = cipher.doFinal(input, (short) 0, (short) input.length, output, (short) 0);

        assertEquals(outLen, KEY_BYTES, "ALG_RSA_NOPAD should return a modulus-wide block");

        BigInteger expected = new BigInteger(1, input).modPow(BigInteger.valueOf(2), modulus);
        BigInteger actual = new BigInteger(1, java.util.Arrays.copyOf(output, outLen));
        assertEquals(actual, expected, "ALG_RSA_NOPAD with e=2 should compute x^2 mod n");
    }
}
