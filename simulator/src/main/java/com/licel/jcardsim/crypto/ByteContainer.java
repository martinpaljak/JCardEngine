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
    // Current length, kept in a 1-element array rather than a field, allocated in the same memory type as
    // data. A transient key's initialized state then clears with the same CLEAR_ON_* event as its bytes; a
    // plain field would survive the event, leaving a wiped key still reporting isInitialized().
    private final short[] len;

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
        switch (memoryType) {
            case JCSystem.MEMORY_TYPE_TRANSIENT_DESELECT -> {
                this.data = JCSystem.makeTransientByteArray((short) fixedSize, JCSystem.CLEAR_ON_DESELECT);
                this.len = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_DESELECT);
            }
            case JCSystem.MEMORY_TYPE_TRANSIENT_RESET -> {
                this.data = JCSystem.makeTransientByteArray((short) fixedSize, JCSystem.CLEAR_ON_RESET);
                this.len = JCSystem.makeTransientShortArray((short) 1, JCSystem.CLEAR_ON_RESET);
            }
            default -> {
                this.data = Simulator.__allocate_bytes(fixedSize);
                this.len = Simulator.__allocate_shorts(1);
            }
        }
    }

    void setBigInteger(BigInteger bInteger) {
        if (bInteger.signum() < 0) {
            throw new IllegalArgumentException("Negative bInteger");
        }
        // toByteArray() prepends a 0x00 sign byte when the high bit is set; strip it
        var array = bInteger.toByteArray();
        short from = (short) (array.length > 1 && array[0] == 0 ? 1 : 0);
        setBytes(array, from, (short) (array.length - from));
    }

    void setBytes(byte[] buff) {
        setBytes(buff, (short) 0, (short) buff.length);
    }

    void setBytes(byte[] buff, short offset, short length) {
        if (length <= 0 || length > data.length) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        if (minimalReadback) {
            Util.arrayCopy(buff, offset, data, (short) 0, length);
            len[0] = length;
            return;
        }
        var padded = new byte[data.length];
        Util.arrayCopyNonAtomic(buff, offset, padded, (short) (data.length - length), length);
        Util.arrayCopy(padded, (short) 0, data, (short) 0, (short) data.length);
        len[0] = (short) data.length;
    }

    void setExact(byte[] buff, short offset, short length) {
        if (length != data.length) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        setBytes(buff, offset, length);
    }

    BigInteger getBigInteger() {
        if (len[0] == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        return new BigInteger(1, data, 0, len[0]);
    }

    byte[] getBytes() {
        if (len[0] == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        var result = new byte[len[0]];
        getBytes(result, (short) 0);
        return result;
    }

    short getBytes(byte[] dest, short offset) {
        if (len[0] == 0) {
            CryptoException.throwIt(CryptoException.UNINITIALIZED_KEY);
        }
        if (dest.length - offset < len[0]) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayCopy(data, (short) 0, dest, offset, len[0]);
        return len[0];
    }

    void clear() {
        Util.arrayFillNonAtomic(data, (short) 0, (short) data.length, (byte) 0);
        len[0] = 0;
    }

    boolean isInitialized() {
        return len[0] > 0;
    }
}
