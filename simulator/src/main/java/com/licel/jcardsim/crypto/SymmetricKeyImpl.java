// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;

public final class SymmetricKeyImpl extends KeyWithParameters implements DESKey, AESKey, HMACKey, KoreanSEEDKey {

    private final ByteContainer key;

    // keySize is in bits; keyType is one of the KeyBuilder TYPE_* constants
    public SymmetricKeyImpl(byte keyType, short keySize, byte memoryType) {
        super(keyType, keySize, memoryType);
        // an HMAC key is set and read back at its own length, bounded by the requested capacity
        key = new ByteContainer(memoryType, keySize / 8, type == KeyBuilder.TYPE_HMAC);
    }

    @Override
    public void clearKey() {
        key.clear();
    }

    // DESKey / AESKey / KoreanSEEDKey: fixed-length key, always the type's full key size
    @Override
    public void setKey(byte[] keyData, short kOff) throws CryptoException, NullPointerException, ArrayIndexOutOfBoundsException {
        key.setBytes(keyData, kOff, (short) (size / 8));
    }

    // HMACKey: variable-length key, copied at the caller-supplied length
    @Override
    public void setKey(byte[] keyData, short kOff, short kLen) throws CryptoException, NullPointerException, ArrayIndexOutOfBoundsException {
        key.setBytes(keyData, kOff, kLen);
    }

    @Override
    public byte getKey(byte[] keyData, short kOff) {
        return (byte) key.getBytes(keyData, kOff);
    }

    @Override
    void setParameters(CipherParameters params) {
        key.setBytes(((KeyParameter) params).getKey());
    }

    @Override
    CipherParameters getParameters() throws CryptoException {
        if (!key.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new KeyParameter(key.getBytes());
    }

    @Override
    public boolean isInitialized() {
        return key.isInitialized();
    }

    @Override
    KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd) {
        return null;
    }

}
