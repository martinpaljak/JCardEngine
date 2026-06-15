// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.security.*;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.security.SecureRandom;
import java.util.List;

/**
 * Implementation of secret key.
 *
 * @see DESKey
 * @see AESKey
 * @see HMACKey
 * @see KoreanSEEDKey
 */
public class SymmetricKeyImpl extends KeyWithParameters implements DESKey, AESKey, HMACKey, KoreanSEEDKey {

    static final List<Byte> KF_DES = List.of(KeyBuilder.TYPE_DES, KeyBuilder.TYPE_DES_TRANSIENT_RESET, KeyBuilder.TYPE_DES_TRANSIENT_DESELECT);
    static final List<Byte> KF_AES = List.of(KeyBuilder.TYPE_AES, KeyBuilder.TYPE_AES_TRANSIENT_RESET, KeyBuilder.TYPE_AES_TRANSIENT_DESELECT);
    static final List<Byte> KF_SEED = List.of(KeyBuilder.TYPE_KOREAN_SEED, KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_RESET, KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_DESELECT);
    static final List<Byte> KF_HMAC = List.of(KeyBuilder.TYPE_HMAC, KeyBuilder.TYPE_HMAC_TRANSIENT_RESET, KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT);

    protected ByteContainer key;

    /**
     * Create new instance of <code>SymmetricKeyImpl</code>
     *
     * @param keyType keyType interface
     * @param keySize keySize in bits
     * @see KeyBuilder
     */
    public SymmetricKeyImpl(byte keyType, short keySize) {
        this.size = keySize;
        this.type = keyType;
        switch (keyType) {
            case KeyBuilder.TYPE_DES_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_AES_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_HMAC_TRANSIENT_DESELECT:
            case KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_DESELECT:
                key = new ByteContainer(JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT);
                break;
            case KeyBuilder.TYPE_DES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_AES_TRANSIENT_RESET:
            case KeyBuilder.TYPE_HMAC_TRANSIENT_RESET:
            case KeyBuilder.TYPE_KOREAN_SEED_TRANSIENT_RESET:
                key = new ByteContainer(JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
                break;
            case KeyBuilder.TYPE_DES:
            case KeyBuilder.TYPE_AES:
            case KeyBuilder.TYPE_HMAC:
            case KeyBuilder.TYPE_KOREAN_SEED:
                key = new ByteContainer(JCSystem.MEMORY_TYPE_PERSISTENT);
                break;
            default:
        }
    }

    /**
     * Clears the key and sets its initialized state to false.
     */
    public void clearKey() {
        key.clear();
    }

    /**
     * Sets the <code>Key</code> data.
     */
    public void setKey(byte[] keyData, short kOff) throws CryptoException, NullPointerException, ArrayIndexOutOfBoundsException {
        key.setBytes(keyData, kOff, (short) (size / 8));
    }

    /**
     * Sets the <code>Key</code> data.
     */
    public void setKey(byte[] keyData, short kOff, short kLen) throws CryptoException, NullPointerException, ArrayIndexOutOfBoundsException {
        key.setBytes(keyData, kOff, kLen);
    }

    /**
     * Returns the <code>Key</code> data in plain text.
     */
    public byte getKey(byte[] keyData, short kOff) {
        return (byte) key.getBytes(keyData, kOff);
    }

    public void setParameters(CipherParameters params) {
        key.setBytes(((KeyParameter) params).getKey());
    }

    /**
     * Return the BouncyCastle <code>KeyParameter</code> of the key
     *
     * @return parameter of the key
     * @throws CryptoException if key not initialized
     * @see KeyParameter
     */
    public CipherParameters getParameters() throws CryptoException {
        if (!key.isInitialized()) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new KeyParameter(key.getBytes());
    }

    public boolean isInitialized() {
        return key.isInitialized();
    }

    @Override
    public KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd) {
        return null;
    }

}
