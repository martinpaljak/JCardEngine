// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2018 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.DHPublicKey;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPublicKeyParameters;

public final class DHPublicKeyImpl extends DHKeyImpl implements DHPublicKey {

    private final ByteContainer y;

    public DHPublicKeyImpl(short size, byte memoryType) {
        super(KeyBuilder.TYPE_DH_PUBLIC, size, memoryType);
        y = new ByteContainer(memoryType, size / 8);
    }

    @Override
    void setParameters(CipherParameters params) {
        super.setParameters(((DHPublicKeyParameters) params).getParameters());
        y.setBigInteger(((DHPublicKeyParameters) params).getY());
    }

    @Override
    public void setY(byte[] bytes, short offset, short length) throws CryptoException {
        y.setBytes(bytes, offset, length);
    }

    @Override
    public short getY(byte[] bytes, short offset) {
        return y.getBytes(bytes, offset);
    }

    @Override
    public void clearKey() {
        y.clear();
        super.clearKey();
    }

    @Override
    public boolean isInitialized() {
        return super.isInitialized() && y.isInitialized();
    }

    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new DHPublicKeyParameters(y.getBigInteger(), (DHParameters) super.getParameters());
    }
}
