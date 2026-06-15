// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.DSAPrivateKey;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;

/**
 * Implementation <code>DSAPrivateKey</code> based
 * on BouncyCastle CryptoAPI.
 * @see DSAPrivateKey
 * @see DSAPrivateKeyParameters
 */
public class DSAPrivateKeyImpl extends DSAKeyImpl implements DSAPrivateKey {

    protected final ByteContainer x;

    /**
     * Construct not-initialized dsa private key
     * @param keySize key size it bits
     * @see KeyBuilder
     */
    public DSAPrivateKeyImpl(short keySize) {
        super(KeyBuilder.TYPE_DSA_PRIVATE, keySize);
        // x is mod q so always fits a prime-width buffer; reads back at its actual length
        x = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, keySize / 8, true);
    }

    @Override
    void setParameters(CipherParameters params) {
        super.setParameters(params);
        x.setBigInteger(((DSAPrivateKeyParameters) params).getX());
    }
    
    public void setX(byte[] buffer, short offset, short length) throws CryptoException {
        x.setBytes(buffer, offset, length);
    }

    public short getX(byte[] buffer, short offset) {
        return x.getBytes(buffer, offset);
    }

    public boolean isInitialized() {
        return super.isInitialized() && x.isInitialized();
    }

    public void clearKey() {
        super.clearKey();
        x.clear();
    }

    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new DSAPrivateKeyParameters(x.getBigInteger(), ((DSAKeyParameters) super.getParameters()).getParameters());
    }
}
