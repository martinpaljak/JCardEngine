// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.Key;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.KeyGenerationParameters;

import java.security.SecureRandom;

/**
 * Base class for all <code>Key</code> instances: carries the JavaCard size/type and the BouncyCastle parameter seam.
 *
 * @see Key
 */
abstract class KeyWithParameters implements Key {

    protected short size;
    protected byte type;

    // key length in bits, e.g. 256 for NIST P-256
    @Override
    public short getSize() {
        return size;
    }

    // KeyBuilder.TYPE_* of this key
    @Override
    public byte getType() {
        return type;
    }

    // cipher key parameters for use with the BouncyCastle Crypto API
    abstract CipherParameters getParameters();

    // keypair generation parameters for use with the BouncyCastle Crypto API
    abstract KeyGenerationParameters getKeyGenerationParameters(SecureRandom rnd);

    // load the key from BouncyCastle cipher parameters
    abstract void setParameters(CipherParameters params);
}
