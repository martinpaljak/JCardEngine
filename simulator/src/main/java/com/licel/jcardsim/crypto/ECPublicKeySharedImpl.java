// SPDX-FileCopyrightText: 2025 dishmaker
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.ECPublicKey;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * Implementation of <code>KeyBuilder.buildKeyWithSharedDomain</code> based
 * on BouncyCastle CryptoAPI.
 * 
 * @see ECPublicKey
 * @see ECPublicKeyParameters
 */
public class ECPublicKeySharedImpl extends ECKeySharedImpl implements ECPublicKey {

    protected final ByteContainer w;

    /**
     * Construct not-initialized ecc public key
     * 
     * @param keyType      key type
     * @param keySize      key size it bits
     * @param sharedDomain key domain parameters, built with
     *                     KeyBuilder.buildKey(KeyBuilder.ALG_TYPE_EC_FP_PARAMETERS..)
     * @see javacard.security.KeyBuilder
     */
    public ECPublicKeySharedImpl(byte keyType, short keySize, byte memoryType, ECKeyImpl sharedDomain) {
        super(keyType, keySize, memoryType, sharedDomain);
        // public point W is an uncompressed point: 04 || X || Y
        w = new ByteContainer(memoryType, 1 + 2 * ((keySize + 7) / 8));
    }

    public void setParameters(CipherParameters params) {
        w.setBytes(((ECPublicKeyParameters) params).getQ().getEncoded(false));
    }

    public void setW(byte[] buffer, short offset, short length) throws CryptoException {
        w.setBytes(buffer, offset, length);
    }

    public short getW(byte[] buffer, short offset) throws CryptoException {
        return w.getBytes(buffer, offset);
    }

    public boolean isInitialized() {
        return isDomainParametersInitialized() && w.isInitialized();
    }

    public void clearKey() {
        super.clearKey();
        w.clear();
    }

    /**
     * Get <code>ECPublicKeyParameters</code>
     * 
     * @return parameters for use with BouncyCastle API
     * @see ECPublicKeyParameters
     */
    public CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        ECDomainParameters dp = getDomainParameters();
        return new ECPublicKeyParameters(dp.getCurve().decodePoint(w.getBytes()), dp);
    }
}
