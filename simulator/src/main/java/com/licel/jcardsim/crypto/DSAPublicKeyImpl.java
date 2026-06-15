// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.DSAPublicKey;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAPublicKeyParameters;

public final class DSAPublicKeyImpl extends DSAKeyImpl implements DSAPublicKey {

    private final ByteContainer y;

    public DSAPublicKeyImpl(short keySize, byte memoryType) {
        super(KeyBuilder.TYPE_DSA_PUBLIC, keySize, memoryType);
        // the public value y = g^x mod p ranges up to p, so it occupies the prime byte length
        y = new ByteContainer(memoryType, keySize / 8);
    }

    @Override
    void setParameters(CipherParameters params) {
        super.setParameters(params);
        y.setBigInteger(((DSAPublicKeyParameters) params).getY());
    }

    @Override
    public void setY(byte[] buffer, short offset, short length) throws CryptoException {
        y.setBytes(buffer, offset, length);
    }

    @Override
    public short getY(byte[] buffer, short offset) {
        return y.getBytes(buffer, offset);
    }

    @Override
    public boolean isInitialized() {
        return super.isInitialized() && y.isInitialized();
    }

    @Override
    public void clearKey() {
        y.clear();
        super.clearKey();
    }

    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new DSAPublicKeyParameters(y.getBigInteger(), ((DSAKeyParameters) super.getParameters()).getParameters());
    }
}
