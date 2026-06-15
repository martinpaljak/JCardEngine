// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.DSAPrivateKey;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DSAKeyParameters;
import org.bouncycastle.crypto.params.DSAPrivateKeyParameters;

public final class DSAPrivateKeyImpl extends DSAKeyImpl implements DSAPrivateKey {

    private final ByteContainer x;

    public DSAPrivateKeyImpl(short keySize, byte memoryType) {
        super(KeyBuilder.TYPE_DSA_PRIVATE, keySize, memoryType);
        // x is mod q so always fits a prime-width buffer; reads back at its actual length
        x = new ByteContainer(memoryType, keySize / 8, true);
    }

    @Override
    void setParameters(CipherParameters params) {
        super.setParameters(params);
        x.setBigInteger(((DSAPrivateKeyParameters) params).getX());
    }

    @Override
    public void setX(byte[] buffer, short offset, short length) throws CryptoException {
        x.setBytes(buffer, offset, length);
    }

    @Override
    public short getX(byte[] buffer, short offset) {
        return x.getBytes(buffer, offset);
    }

    @Override
    public boolean isInitialized() {
        return super.isInitialized() && x.isInitialized();
    }

    @Override
    public void clearKey() {
        x.clear();
        super.clearKey();
    }

    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new DSAPrivateKeyParameters(x.getBigInteger(), ((DSAKeyParameters) super.getParameters()).getParameters());
    }
}
