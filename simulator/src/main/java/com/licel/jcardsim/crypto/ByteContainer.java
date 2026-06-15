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
 * Fixed-capacity byte buffer for a key component. The backing array is allocated once at
 * construction in the requested memory type and is never reallocated: the setters only copy
 * bytes into it.
 */
public final class ByteContainer {

    private final byte[] data;
    private final boolean minimalReadback;
    private short length = 0;

    /**
     * Construct a <code>ByteContainer</code> of the given memory type pinned to a fixed width. The
     * applet {@link #setBytes} path demands exactly <code>fixedSize</code> bytes; only the internal
     * {@link #setBigInteger} path left-pads a shorter magnitude to the width.
     * @param memoryType one of <code>JCSystem.MEMORY_TYPE_*</code>
     * @param fixedSize fixed component width in bytes
     */
    public ByteContainer(byte memoryType, int fixedSize) {
        this(memoryType, fixedSize, false);
    }

    /**
     * Construct a <code>ByteContainer</code> as in {@link #ByteContainer(byte, int)}, but when
     * <code>minimalReadback</code> is true the value is stored verbatim up to the fixed buffer
     * capacity and read back at its own length. Use for a value bounded by a known width yet with no
     * canonical length: RSA public exponent, EC private scalar, DSA/DH subprime or private value.
     * @param memoryType one of <code>JCSystem.MEMORY_TYPE_*</code>
     * @param fixedSize fixed buffer capacity in bytes
     * @param minimalReadback store and read back the verbatim length instead of the fixed width
     */
    public ByteContainer(byte memoryType, int fixedSize, boolean minimalReadback) {
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

    public void setBigInteger(BigInteger bInteger) {
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

    public void setBytes(byte[] buff) {
        setBytes(buff, (short) 0, (short) buff.length);
    }

    public void setBytes(byte[] buff, short offset, short length) {
        // a fixed-width slot demands the exact width; a minimal slot only bounds capacity
        if (minimalReadback ? length > data.length : length != data.length) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayCopy(buff, offset, data, (short) 0, length);
        this.length = length;
    }

    public BigInteger getBigInteger() {
        if (length == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new BigInteger(1, data, 0, length);
    }

    /**
     * Copy of the contents as a fresh byte array, for the BouncyCastle Crypto API.
     */
    public byte[] getBytes() {
        if (length == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        byte[] result = new byte[length];
        getBytes(result, (short) 0);
        return result;
    }

    public short getBytes(byte[] dest, short offset) {
        if (length == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (dest.length - offset < length) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayCopy(data, (short) 0, dest, offset, length);
        return length;
    }

    public void clear() {
        Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0);
        length = 0;
    }

    public boolean isInitialized() {
        return length > 0;
    }
}
