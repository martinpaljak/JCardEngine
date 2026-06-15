// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
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

/**
 * Implementation
 * <code>RSAPublic/RSAPrivate</code> based on BouncyCastle CryptoAPI.
 *
 * @see RSAPrivateKey
 * @see RSAPublicKey
 * @see RSAKeyParameters
 */
public class RSAKeyImpl extends KeyWithParameters implements RSAPrivateKey, RSAPublicKey {

    // JavaCard API maximum public exponent length
    private static final short PUBLIC_EXPONENT_MAX_BYTES = 4;

    protected final ByteContainer exponent;
    protected final ByteContainer modulus;
    protected boolean isPrivate;

    /**
     * Construct not-initialized rsa key
     *
     * @param isPrivate true if private key
     * @param size      key size it bits (modulus size)
     * @see KeyBuilder
     */
    public RSAKeyImpl(boolean isPrivate, short size) {
        this.isPrivate = isPrivate;
        this.size = size;
        type = isPrivate ? KeyBuilder.TYPE_RSA_PRIVATE : KeyBuilder.TYPE_RSA_PUBLIC;
        modulus = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, size / 8);
        exponent = isPrivate
                ? new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, size / 8)
                : new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, PUBLIC_EXPONENT_MAX_BYTES, true);
    }

    @Override
    void setParameters(CipherParameters params) {
        RSAKeyParameters rsa = (RSAKeyParameters) params;
        modulus.setBigInteger(rsa.getModulus());
        exponent.setBigInteger(rsa.getExponent());
    }

    public short getExponent(byte[] buffer, short offset) {
        return exponent.getBytes(buffer, offset);
    }

    public short getModulus(byte[] buffer, short offset) {
        return modulus.getBytes(buffer, offset);
    }

    public void setExponent(byte[] buffer, short offset, short length) throws CryptoException {
        exponent.setBytes(buffer, offset, length);
    }

    public void setModulus(byte[] buffer, short offset, short length) throws CryptoException {
        modulus.setBytes(buffer, offset, length);
    }

    public void clearKey() {
        exponent.clear();
        modulus.clear();
    }

    public boolean isInitialized() {
        return exponent.isInitialized() && modulus.isInitialized();
    }

    /**
     * Get
     * <code>RSAKeyParameters</code>
     *
     * @return parameters for use with BouncyCastle API
     * @see RSAKeyParameters
     */
    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new RSAKeyParameters(isPrivate, modulus.getBigInteger(), exponent.getBigInteger());
    }

    /**
     * Get
     * <code>RSAKeyGenerationParameters</code>
     *
     * @param rnd Secure Random Generator
     * @return parameters for use with BouncyCastle API
     */
    @Override
    KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd) {
        if (!isPrivate && exponent.isInitialized()) {
            return new RSAKeyGenerationParameters(exponent.getBigInteger(), rnd, size, 80);
        }
        return getDefaultKeyGenerationParameters(size, rnd);
    }

    /**
     * Get default
     * <code>RSAKeyGenerationParameters</code>
     *
     * @param keySize key size in bits
     * @param rnd     Secure Random Generator
     * @return parameters for use with BouncyCastle API
     */
    static KeyGenerationParameters getDefaultKeyGenerationParameters(short keySize, SecureRandom rnd) {
        return new RSAKeyGenerationParameters(new BigInteger("10001", 16), rnd, keySize, 80);
    }
}
