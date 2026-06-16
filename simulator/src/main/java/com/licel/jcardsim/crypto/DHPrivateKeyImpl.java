// SPDX-FileCopyrightText: 2026 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2018 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.DHPrivateKey;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;

public final class DHPrivateKeyImpl extends DHKeyImpl implements DHPrivateKey {

    private final ByteContainer x;

    public DHPrivateKeyImpl(short size, byte memoryType) {
        super(KeyBuilder.TYPE_DH_PRIVATE, size, memoryType);
        // x is bounded by p, so a prime-width buffer suffices; returns only significant bytes
        x = new ByteContainer(memoryType, size / 8, true);
    }

    @Override
    void setParameters(CipherParameters params) {
        super.setParameters(((DHPrivateKeyParameters) params).getParameters());
        x.setBigInteger(((DHPrivateKeyParameters) params).getX());
    }

    @Override
    public void setX(byte[] bytes, short offset, short length) throws CryptoException {
        x.setBytes(bytes, offset, length);
    }

    @Override
    public short getX(byte[] bytes, short offset) {
        return x.getBytes(bytes, offset);
    }

    @Override
    public void clearKey() {
        x.clear();
        super.clearKey();
    }

    @Override
    public boolean isInitialized() {
        return super.isInitialized() && x.isInitialized();
    }

    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new DHPrivateKeyParameters(x.getBigInteger(), (DHParameters) super.getParameters());
    }
}
