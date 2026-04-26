// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.ECPublicKey;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

/**
 * Implementation <code>ECPublicKey</code> based
 * on BouncyCastle CryptoAPI.
 * @see ECPublicKey
 * @see ECPublicKeyParameters
 */
public class ECPublicKeyImpl extends ECKeyImpl implements ECPublicKey {

    protected ByteContainer w;

    /**
     * Construct not-initialized ecc public key
     * @param keyType key type
     * @param keySize key size it bits
     * @see javacard.security.KeyBuilder
     */
    public ECPublicKeyImpl(byte keyType, short keySize, byte memoryType) {
        super(keyType, keySize, memoryType);
        w = new ByteContainer(memoryType);
    }

    /**
     * Construct and initialize ecc key with ECPublicKeyParameters.
     * Use in KeyPairImpl
     * @see javacard.security.KeyPair
     * @see ECPublicKeyParameters
     * @param params key params from BouncyCastle API
     */
    public ECPublicKeyImpl(ECPublicKeyParameters params) {
        super(params);
        setParameters(params);
    }
 
     public void setParameters(CipherParameters params){
        w.setBytes(((ECPublicKeyParameters)params).getQ().getEncoded(false));
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
     * @return parameters for use with BouncyCastle API
     * @see ECPublicKeyParameters
     */
    public CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        ECDomainParameters dp = getDomainParameters();
        return new ECPublicKeyParameters(dp.getCurve().decodePoint(w.getBytes(JCSystem.CLEAR_ON_RESET)), dp);
    }
}
