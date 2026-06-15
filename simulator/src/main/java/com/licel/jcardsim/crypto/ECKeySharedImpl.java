// SPDX-FileCopyrightText: 2025 dishmaker
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.ECKey;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;

import java.security.SecureRandom;

/**
 * Base class for
 * <code>ECPublicKeyImpl/ECPrivateKeyImpl</code> on BouncyCastle CryptoAPI.
 *
 * @see ECKey
 */
public abstract class ECKeySharedImpl extends KeyImpl implements ECKey {
    private ECKeyImpl sharedDomain;

    /**
     * Construct not-initialized ecc key
     *
     * @param keyType      - key type
     * @param keySize      - key size in bits
     * @param sharedDomain key domain parameters, built with
     *                     KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PARAMETERS..)
     * @see KeyPair
     * @see KeyBuilder
     */
    public ECKeySharedImpl(byte keyType, short keySize, byte memoryType, ECKeyImpl sharedDomain) {
        this.size = keySize;
        this.type = keyType;
        this.sharedDomain = sharedDomain;
    }

    public void clearKey() {
        // shared domain is referenced by sibling keys; clearing it here would corrupt them, so clear only own S/W
    }

    protected boolean isDomainParametersInitialized() {
        return sharedDomain.isDomainParametersInitialized();
    }

    public void setFieldFP(byte[] buffer, short offset, short length) throws CryptoException {
        sharedDomain.setFieldFP(buffer, offset, length);
    }

    public void setFieldF2M(short e) throws CryptoException {
        setFieldF2M(e, (short) 0, (short) 0);
    }

    public void setFieldF2M(short e1, short e2, short e3) throws CryptoException {
        sharedDomain.setFieldF2M(e1, e2, e3);
    }

    public void setA(byte[] buffer, short offset, short length) throws CryptoException {
        sharedDomain.setA(buffer, offset, length);
    }

    public void setB(byte[] buffer, short offset, short length) throws CryptoException {
        sharedDomain.setB(buffer, offset, length);
    }

    public void setG(byte[] buffer, short offset, short length) throws CryptoException {
        sharedDomain.setG(buffer, offset, length);
    }

    public void setR(byte[] buffer, short offset, short length) throws CryptoException {
        sharedDomain.setR(buffer, offset, length);
    }

    public void setK(short K) {
        sharedDomain.setK(K);
    }

    public short getField(byte[] buffer, short offset) throws CryptoException {
        return sharedDomain.getField(buffer, offset);
    }

    public short getA(byte[] buffer, short offset) throws CryptoException {
        return sharedDomain.getA(buffer, offset);
    }

    public short getB(byte[] buffer, short offset) throws CryptoException {
        return sharedDomain.getB(buffer, offset);
    }

    public short getG(byte[] buffer, short offset) throws CryptoException {
        return sharedDomain.getG(buffer, offset);
    }

    public short getR(byte[] buffer, short offset) throws CryptoException {
        return sharedDomain.getR(buffer, offset);
    }

    public short getK() throws CryptoException {
        return sharedDomain.getK();
    }

    /**
     * Get
     * <code>ECDomainParameters</code>
     *
     * @return parameters for use with BouncyCastle API
     * @see ECDomainParameters
     */
    public ECDomainParameters getDomainParameters() {
        return sharedDomain.getDomainParameters();
    }

    /**
     * Set
     * <code>ECDomainParameters</code> for EC curve
     *
     * @param parameters
     * @see ECDomainParameters
     */
    final void setDomainParameters(ECDomainParameters parameters) {
        sharedDomain.setDomainParameters(parameters);
    }

    /**
     * Get
     * <code>ECKeyGenerationParameters</code>
     *
     * @param rnd Secure Random Generator
     * @return parameters for use with BouncyCastle API
     */
    public KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd) {
        return sharedDomain.getKeyGenerationParameters(rnd);
    }

    public void copyDomainParametersFrom(ECKey eckey) throws CryptoException {
        sharedDomain.copyDomainParametersFrom(eckey);
    }
}
