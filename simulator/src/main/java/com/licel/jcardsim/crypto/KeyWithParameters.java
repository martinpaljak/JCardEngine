// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.Key;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

public abstract class KeyWithParameters implements Key {

    protected short size;
    // persistent KeyBuilder.TYPE_* constant, for internal comparisons
    protected byte type;
    protected byte memoryType;
    private final KeyFamily family;

    protected KeyWithParameters(byte type, short size, byte memoryType) {
        this.family = KeyFamily.byType(type);
        this.type = family == null ? type : family.persistent();
        this.size = size;
        this.memoryType = memoryType;
    }

    // key length in bits, e.g. 256 for NIST P-256
    @Override
    public short getSize() {
        return size;
    }

    // KeyBuilder.TYPE_* of this key, per its memory type
    @Override
    public byte getType() {
        return family == null ? type : family.type(memoryType);
    }

    // JCSystem.MEMORY_TYPE_* constant for this key
    public byte getMemoryType() {
        return memoryType;
    }

    // cipher key parameters for use with the BouncyCastle Crypto API
    abstract CipherParameters getParameters();

    // keypair generation parameters for use with the BouncyCastle Crypto API
    abstract KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd);

    // load the key from BouncyCastle cipher parameters
    abstract void setParameters(CipherParameters params);
}
