// SPDX-FileCopyrightText: 2018 Licel Corporation.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.security.CryptoException;
import javacard.security.DHPrivateKey;
import javacard.security.KeyBuilder;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.DHParameters;
import org.bouncycastle.crypto.params.DHPrivateKeyParameters;

public final class DHPrivateKeyImpl extends DHKeyImpl implements DHPrivateKey {
        
    protected final ByteContainer x;

    public DHPrivateKeyImpl(short size) {
        super(size);
        type = KeyBuilder.TYPE_DH_PRIVATE;
        // x is bounded by p, so a prime-width buffer suffices; returns only significant bytes
        x = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT, size / 8, true);
    }

    @Override
    public void setParameters(CipherParameters params) {
        super.setParameters(((DHPrivateKeyParameters) params).getParameters());
        x.setBigInteger(((DHPrivateKeyParameters) params).getX());
    }
    
    public void setX(byte[] bytes, short offset, short length) throws CryptoException {
        x.setBytes(bytes, offset, length);
    }

    public short getX(byte[] bytes, short offset) {
        return x.getBytes(bytes, offset);
    }
    
    @Override
    public void clearKey() {
        super.clearKey();
        x.clear();
    }

    @Override
    public boolean isInitialized() {
        return super.isInitialized() && x.isInitialized();
    }
    
    @Override
    public CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new DHPrivateKeyParameters(x.getBigInteger(), (DHParameters) super.getParameters());
    }
}
