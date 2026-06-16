// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECPrivateKeyParameters;

public final class ECPrivateKeyImpl extends ECKeyImpl implements ECPrivateKey {

    private final ByteContainer s;

    public ECPrivateKeyImpl(byte keyType, short keySize, byte memoryType) {
        super(keyType, keySize, memoryType);
        // stored as-is, no padding; capacity equals the curve order in bytes
        s = new ByteContainer(memoryType, ECDomain.orderBytes(keySize), true);
    }

    public ECPrivateKeyImpl(byte keyType, short keySize, byte memoryType, ECKeyImpl shared) {
        super(keyType, keySize, memoryType, shared);
        // stored as-is, no padding; capacity equals the curve order in bytes
        s = new ByteContainer(memoryType, ECDomain.orderBytes(keySize), true);
    }

    @Override
    void setParameters(CipherParameters params) {
        s.setBigInteger(((ECPrivateKeyParameters) params).getD());
    }

    @Override
    public void setS(byte[] buffer, short offset, short length) throws CryptoException {
        s.setBytes(buffer, offset, length);
    }

    @Override
    public short getS(byte[] buffer, short offset) throws CryptoException {
        return s.getBytes(buffer, offset);
    }

    @Override
    public boolean isInitialized() {
        return isDomainParametersInitialized() && s.isInitialized();
    }

    @Override
    public void clearKey() {
        s.clear();
        super.clearKey();
    }

    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new ECPrivateKeyParameters(s.getBigInteger(), getDomainParameters());
    }
}
