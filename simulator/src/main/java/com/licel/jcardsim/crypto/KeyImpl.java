// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.security.Key;

/**
 * Base class for all <code>Key</code> instances.
 *
 * @see Key
 */
public abstract class KeyImpl implements Key, KeyWithParameters {

    protected short size;
    protected byte type;

    /**
     * Returns keyLength, for example 256 for NistP256.
     */
    public short getSize() {
        return size;
    }

    /**
     * Returns key type, for example KeyBuilder.TYPE_EC_FP_PUBLIC.
     */
    public byte getType() {
        return type;
    }
}
