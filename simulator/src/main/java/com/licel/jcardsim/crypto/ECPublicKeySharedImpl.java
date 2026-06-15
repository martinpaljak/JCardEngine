// SPDX-FileCopyrightText: 2025 dishmaker
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.CryptoException;
import javacard.security.ECPublicKey;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;

public final class ECPublicKeySharedImpl extends ECKeySharedImpl implements ECPublicKey {

    private final ByteContainer w;

    public ECPublicKeySharedImpl(byte keyType, short keySize, byte memoryType, ECKeyImpl sharedDomain) {
        super(keyType, keySize, memoryType, sharedDomain);
        // public point W is an uncompressed point: 04 || X || Y
        w = new ByteContainer(memoryType, 1 + 2 * ((keySize + 7) / 8));
    }

    @Override
    void setParameters(CipherParameters params) {
        w.setBytes(((ECPublicKeyParameters) params).getQ().getEncoded(false));
    }

    @Override
    public void setW(byte[] buffer, short offset, short length) throws CryptoException {
        w.setBytes(buffer, offset, length);
    }

    @Override
    public short getW(byte[] buffer, short offset) throws CryptoException {
        return w.getBytes(buffer, offset);
    }

    @Override
    public boolean isInitialized() {
        return isDomainParametersInitialized() && w.isInitialized();
    }

    @Override
    public void clearKey() {
        w.clear();
        super.clearKey();
    }

    @Override
    CipherParameters getParameters() {
        if (!isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        ECDomainParameters dp = getDomainParameters();
        return new ECPublicKeyParameters(dp.getCurve().decodePoint(w.getBytes()), dp);
    }
}
