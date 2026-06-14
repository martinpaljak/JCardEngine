// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import com.licel.jcardsim.base.Simulator;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.CryptoException;

import java.math.BigInteger;

/**
 * This class contains byte array, initialization flag of this
 * array and memory type.
 */
public final class ByteContainer {

    private byte[] data;
    private byte memoryType;
    private short length = 0;
    private short fixedSize = 0;
    private boolean minimalReadback = false;

    /**
     * Construct <code>ByteContainer</code>
     * with memory type <code>JCSystem.MEMORY_TYPE_PERSISTENT</code>
     */
    public ByteContainer() {
        this(JCSystem.MEMORY_TYPE_PERSISTENT);
    }

    /**
     * Construct <code>ByteContainer</code>
     * with defined memory type
     * @param memoryType  memoryType from JCSystem.MEMORY_..
     */
    public ByteContainer(byte memoryType) {
        this.memoryType = memoryType;
    }

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
        this.memoryType = memoryType;
        this.fixedSize = (short) fixedSize;
        this.minimalReadback = minimalReadback;
    }

    /**
     * Construct <code>ByteContainer</code>
     * with memory type <code>JCSystem.MEMORY_TYPE_PERSISTENT</code>
     * and fills it by byte representation of <code>BigInteger</code>
     * @param bInteger <code>BigInteger</code> object
     * @throws java.lang.IllegalArgumentException if bInteger is negative
     */
    // XXX: consider removal
    public ByteContainer(BigInteger bInteger) {
        setBigInteger(bInteger);
    }

    /**
     * Construct <code>ByteContainer</code>
     * with memory type <code>JCSystem.MEMORY_TYPE_PERSISTENT</code>
     * and fills it by defined byte array
     * @param buff byte array
     * @param offset offset in byte array
     * @param length length of data in byte array
     */
    public ByteContainer(byte[] buff, short offset, short length) {
        setBytes(buff, offset, length);
    }

    /**
     * Fills <code>ByteContainer</code>by byte representation of <code>BigInteger</code>
     * @param bInteger <code>BigInteger</code> object
     * @throws java.lang.IllegalArgumentException if bInteger is negative
     */
    public void setBigInteger(BigInteger bInteger) {
        if (bInteger.signum() < 0) {
            throw new IllegalArgumentException("Negative bInteger");
        }
        // toByteArray() prepends a 0x00 sign byte when the high bit is set; strip it
        var array = bInteger.toByteArray();
        short from = (short) (array.length > 1 && array[0] == 0 ? 1 : 0);
        short mlen = (short) (array.length - from);
        if (fixedSize > 0 && !minimalReadback) {
            // a generated fixed-width component is stored left zero-padded to its exact width
            if (mlen > fixedSize) {
                CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
            }
            var padded = new byte[fixedSize];
            System.arraycopy(array, from, padded, fixedSize - mlen, mlen);
            setBytes(padded, (short) 0, fixedSize);
        } else {
            setBytes(array, from, mlen);
        }
    }

    /**
     * Fills <code>ByteContainer</code>by defined byte array
     * @param buff byte array
     */
    public void setBytes(byte[] buff) {
        setBytes(buff, (short) 0, (short) buff.length);
    }

    /**
     * Fills <code>ByteContainer</code>by defined byte array
     * @param buff byte array
     * @param offset offset in byte array
     * @param length length of data in byte array
     */
    public void setBytes(byte[] buff, short offset, short length) {
        // a fixed-width slot demands the exact width; a minimal slot only bounds capacity
        if (fixedSize > 0 && (minimalReadback ? length > fixedSize : length != fixedSize)) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        short capacity = fixedSize > 0 ? fixedSize : length;
        if (data == null || data.length != capacity) {
            switch (memoryType) {
                case JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT:
                    data = JCSystem.makeTransientByteArray(capacity, JCSystem.CLEAR_ON_DESELECT);
                    break;
                case JCSystem.MEMORY_TYPE_TRANSIENT_RESET:
                    data = JCSystem.makeTransientByteArray(capacity, JCSystem.CLEAR_ON_RESET);
                    break;
                default:
                    data = Simulator.allocateBytes(capacity);
                    break;
            }
        }
        Util.arrayCopy(buff, offset, data, (short) 0, length);
        this.length = length;
    }

    /**
     * Return <code>BigInteger</code> representation of the <code>ByteContainer</code>
     * @return BigInteger
     */
    public BigInteger getBigInteger() {
        if (length == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new BigInteger(1, data, 0, length);
    }

    /**
     * Return transient plain byte array representation of the <code>ByteContainer</code>
     * @param event type of transient byte array
     * @return plain byte array
     */
    // XXX: reconsider the need for this
    public byte[] getBytes(byte event) {
        if (length == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        byte[] result = JCSystem.makeTransientByteArray(length, event);
        getBytes(result, (short) 0);
        return result;
    }

    /**
     * Copy byte array representation of the <code>ByteContainer</code>
     * @param dest destination byte array
     * @param offset destination byte array offset
     * @return bytes copied
     */
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

    /**
     * Clear internal structure of the <code>ByteContainer</code>
     */
    public void clear() {
        if (data != null) {
            Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0);
        }
        length = 0;
    }

    /**
     * Reports the initialized state of the container.
     * @return <code>true</code> if the container has been initialized
     */
    public boolean isInitialized() {
        return length > 0;
    }
}
