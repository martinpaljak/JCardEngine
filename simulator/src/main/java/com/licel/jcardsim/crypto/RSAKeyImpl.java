// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.KeyBuilder;
import javacard.security.RSAPrivateKey;
import javacard.security.RSAPublicKey;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSAKeyImpl extends KeyWithParameters implements RSAPrivateKey, RSAPublicKey {

    private final ByteContainer exponent;
    private final ByteContainer modulus;

    public RSAKeyImpl(byte keyType, short size, byte memoryType) {
        super(keyType, size, memoryType);
        if (size < 0 || size > KeyBuilder.LENGTH_RSA_4096) {
            CryptoException.throwIt(CryptoException.NO_SUCH_ALGORITHM);
        }
        modulus = new ByteContainer(memoryType, size / 8);
        exponent = new ByteContainer(memoryType, size / 8, !isPrivate());
    }

    private boolean isPrivate() {
        return type != KeyBuilder.TYPE_RSA_PUBLIC;
    }

    @Override
    void setParameters(CipherParameters params) {
        var rsa = (RSAKeyParameters) params;
        modulus.setBigInteger(rsa.getModulus());
        exponent.setBigInteger(rsa.getExponent());
    }

    @Override
    public short getExponent(byte[] buffer, short offset) {
        return exponent.getBytes(buffer, offset);
    }

    @Override
    public short getModulus(byte[] buffer, short offset) {
        return modulus.getBytes(buffer, offset);
    }

    @Override
    public void setExponent(byte[] buffer, short offset, short length) throws CryptoException {
        exponent.setBytes(buffer, offset, length);
    }

    @Override
    public void setModulus(byte[] buffer, short offset, short length) throws CryptoException {
        modulus.setBytes(buffer, offset, length);
    }

    @Override
    public void clearKey() {
        exponent.clear();
        modulus.clear();
    }

    @Override
    public boolean isInitialized() {
        return exponent.isInitialized() && modulus.isInitialized();
    }

    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        var n = modulus.getBigInteger();
        var e = exponent.getBigInteger();
        // JavaCard imposes no validity constraints on a raw RSA exponent, but BouncyCastle rejects
        // an even *public* exponent. JCMathLib-style code legitimately sets e = 2 to use the RSA
        // engine as a modular squaring primitive. Present such a key to BC as a private key, which
        // takes the same plain modPow path without the public-key validation.
        return new RSAKeyParameters(isPrivate() || !e.testBit(0), n, e);
    }

    @Override
    KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd) {
        if (!isPrivate() && exponent.isInitialized()) {
            return new RSAKeyGenerationParameters(exponent.getBigInteger(), rnd, size, 80);
        }
        return getDefaultKeyGenerationParameters(size, rnd);
    }

    static KeyGenerationParameters getDefaultKeyGenerationParameters(short keySize, SecureRandom rnd) {
        return new RSAKeyGenerationParameters(new BigInteger("10001", 16), rnd, keySize, 80);
    }
}
