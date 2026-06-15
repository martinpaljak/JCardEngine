// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.DSAPublicKey;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;

/**
 * Implementation <code>DSAPublicKey</code> based
 * on BouncyCastle CryptoAPI.
 *
 * @see DSAPublicKey
 * @see DSAPublicKeyParameters
 */
public class DSAPublicKeyImpl extends DSAKeyImpl implements DSAPublicKey {

    protected final ByteContainer y;

    /**
     * Construct not-initialized dsa public key
     *
     * @param keySize key size it bits
     * @see KeyBuilder
     */
    public DSAPublicKeyImpl(short keySize) {
        super(KeyBuilder.TYPE_DSA_PUBLIC, keySize);
        // the public value y = g^x mod p ranges up to p, so it occupies the prime byte length
        y = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, keySize / 8);
    }

    @Override
    void setParameters(CipherParameters params) {
        super.setParameters(params);
        y.setBigInteger(((DSAPublicKeyParameters) params).getY());
    }

    public void setY(byte[] buffer, short offset, short length) throws CryptoException {
        y.setBytes(buffer, offset, length);
    }

    public short getY(byte[] buffer, short offset) {
        return y.getBytes(buffer, offset);
    }

    public boolean isInitialized() {
        return super.isInitialized() && y.isInitialized();
    }

    public void clearKey() {
        super.clearKey();
        y.clear();
    }

    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new DSAPublicKeyParameters(y.getBigInteger(), ((DSAKeyParameters) super.getParameters()).getParameters());
    }
}
