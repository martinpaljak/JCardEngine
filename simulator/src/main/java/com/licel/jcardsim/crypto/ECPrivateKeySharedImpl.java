// SPDX-FileCopyrightText: 2025 dishmaker
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

/**
 * Implementation of <code>KeyBuilder.buildKeyWithSharedDomain</code> based
 * on BouncyCastle CryptoAPI.
 * 
 * @see ECPrivateKey
 * @see ECPrivateKeyParameters
 */
public class ECPrivateKeySharedImpl extends ECKeySharedImpl implements ECPrivateKey {

    protected final ByteContainer s;

    /**
     * Construct not-initialized ecc private key
     * 
     * @param keyType      key type
     * @param keySize      key size it bits
     * @param sharedDomain key domain parameters, built with
     *                     KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PARAMETERS..)
     *
     * @see javacard.security.KeyBuilder
     */
    public ECPrivateKeySharedImpl(byte keyType, short keySize, byte memoryType, ECKeyImpl sharedDomain) {
        super(keyType, keySize, memoryType, sharedDomain);
        // the secret scalar is stored verbatim within an order-width buffer
        s = new ByteContainer(memoryType, ECKeyImpl.orderBytes(keyType, keySize), true);
    }

    public void setParameters(CipherParameters params) {
        s.setBigInteger(((ECPrivateKeyParameters) params).getD());
    }

    public void setS(byte[] buffer, short offset, short length) throws CryptoException {
        s.setBytes(buffer, offset, length);
    }

    public short getS(byte[] buffer, short offset) throws CryptoException {
        return s.getBytes(buffer, offset);
    }

    public boolean isInitialized() {
        return isDomainParametersInitialized() && s.isInitialized();
    }

    public void clearKey() {
        super.clearKey();
        s.clear();
    }

    /**
     * Get <code>ECPrivateKeyParameters</code>
     * 
     * @return parameters for use with BouncyCastle API
     * @see ECPrivateKeyParameters
     */
    public CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new ECPrivateKeyParameters(s.getBigInteger(), getDomainParameters());
    }
}
