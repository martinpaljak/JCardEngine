// SPDX-FileCopyrightText: 2025 Martin Paljak <martin@martinpaljak.net>
// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;

import java.math.BigInteger;

/**
 * Fixed-capacity byte buffer for a key component. The backing array is allocated once in the requested memory type and never reallocated.
 */
final class ByteContainer {

    private final byte[] data;
    private final boolean minimalReadback;
    private short length = 0;

    ByteContainer(byte memoryType, int fixedSize) {
        this(memoryType, fixedSize, false);
    }

    // minimalReadback: store verbatim up to capacity, read back at actual length. Use for values with no canonical width (RSA public exponent,
    // EC private scalar, DSA/DH subprime or private value). Otherwise pinned to fixedSize.
    ByteContainer(byte memoryType, int fixedSize, boolean minimalReadback) {
        if (fixedSize < 0 || fixedSize > Short.MAX_VALUE) {
            throw new IllegalArgumentException("fixedSize out of range: " + fixedSize);
        }
        this.minimalReadback = minimalReadback;
        this.data = allocate(memoryType, fixedSize);
    }

    private static byte[] allocate(byte memoryType, int capacity) {
        switch (memoryType) {
            case JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT:
                return JCSystem.makeTransientByteArray((short) capacity, JCSystem.CLEAR_ON_DESELECT);
            case JCSystem.MEMORY_TYPE_TRANSIENT_RESET:
                return JCSystem.makeTransientByteArray((short) capacity, JCSystem.CLEAR_ON_RESET);
            default:
                return Simulator.allocateBytes(capacity);
        }
    }

    void setBigInteger(BigInteger bInteger) {
        if (bInteger.signum() < 0) {
            throw new IllegalArgumentException("Negative bInteger");
        }
        // toByteArray() prepends a 0x00 sign byte when the high bit is set; strip it
        var array = bInteger.toByteArray();
        short from = (short) (array.length > 1 && array[0] == 0 ? 1 : 0);
        short mlen = (short) (array.length - from);
        if (minimalReadback) {
            setBytes(array, from, mlen);
        } else {
            // a fixed-width component is stored left zero-padded to its exact width
            if (mlen > data.length) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            var padded = new byte[data.length];
            System.arraycopy(array, from, padded, data.length - mlen, mlen);
            setBytes(padded, (short) 0, (short) data.length);
        }
    }

    void setBytes(byte[] buff) {
        setBytes(buff, (short) 0, (short) buff.length);
    }

    void setBytes(byte[] buff, short offset, short length) {
        // a fixed-width slot demands the exact width; a minimal slot only bounds capacity
        if (minimalReadback ? length > data.length : length != data.length) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayCopy(buff, offset, data, (short) 0, length);
        this.length = length;
    }

    BigInteger getBigInteger() {
        if (length == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new BigInteger(1, data, 0, length);
    }

    byte[] getBytes() {
        if (length == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        var result = new byte[length];
        getBytes(result, (short) 0);
        return result;
    }

    short getBytes(byte[] dest, short offset) {
        if (length == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (dest.length - offset < length) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayCopy(data, (short) 0, dest, offset, length);
        return length;
    }

    void clear() {
        Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0);
        length = 0;
    }

    boolean isInitialized() {
        return length > 0;
    }
}
