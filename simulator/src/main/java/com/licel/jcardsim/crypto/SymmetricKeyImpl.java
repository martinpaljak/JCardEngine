// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;
import java.util.List;

public final class SymmetricKeyImpl extends KeyWithParameters implements DESKey, AESKey, HMACKey, KoreanSEEDKey {

    static final List<Byte> KF_DES = List.of(KeyBuilder.TYPE_DES, KeyBuilder.TYPE_DES_TRANSIENT_RESET, KeyBuilder.TYPE_DES_TRANSIENT_DESELECT);
    static final List<Byte> KF_AES = List.of(KeyBuilder.TYPE_AES, KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.TYPE_AES_TRANSIENT_DESELECT);
    static final List<Byte> KF_SEED = List.of(KeyBuilder.TYPE_KOREAN_SEED, KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_RESET, KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_DESELECT);
    static final List<Byte> KF_HMAC = List.of(KeyBuilder.TYPE_HMAC, KeyBuilder.TYPE_HMAC_TRANSIENT_RESET, KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT);

    private final ByteContainer key;

    // keySize is in bits; keyType is one of the KeyBuilder TYPE_* constants
    public SymmetricKeyImpl(byte keyType, short keySize, byte memoryType) {
        super(keyType, keySize, memoryType);
        // an HMAC key is set and read back at its own length, bounded by the requested capacity
        key = new ByteContainer(memoryType, keySize / 8, KF_HMAC.contains(keyType));
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
