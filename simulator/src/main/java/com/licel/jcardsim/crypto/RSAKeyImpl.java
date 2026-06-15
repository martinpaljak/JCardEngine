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

    // JavaCard API maximum public exponent length
    private static final short PUBLIC_EXPONENT_MAX_BYTES = 4;

    private final ByteContainer exponent;
    private final ByteContainer modulus;

    public RSAKeyImpl(byte keyType, short size, byte memoryType) {
        super(keyType, size, memoryType);
        modulus = new ByteContainer(memoryType, size / 8);
        exponent = isPrivate()
                ? new ByteContainer(memoryType, size / 8)
                : new ByteContainer(memoryType, PUBLIC_EXPONENT_MAX_BYTES, true);
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
        return new RSAKeyParameters(isPrivate(), modulus.getBigInteger(), exponent.getBigInteger());
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
