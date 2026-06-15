// SPDX-FileCopyrightText: 2011 Licel LLC.
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.crypto;

import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.Checksum;
import javacard.security.CryptoException;

// ISO/IEC 3309 16-bit CRC (HDLC frame check sequence)
public final class CRC16 extends Checksum {

    static final byte LENGTH = 2;
    private final byte[] crc16;

    public CRC16() {
        crc16 = JCSystem.makeTransientByteArray(LENGTH, JCSystem.CLEAR_ON_DESELECT);
    }

    @Override
    public byte getAlgorithm() {
        return ALG_ISO3309_CRC16;
    }

    @Override
    public void init(byte[] bArray, short bOff, short bLen)
            throws CryptoException {
        if (bLen != LENGTH) {
            CryptoException.throwIt(CryptoException.ILLEGAL_VALUE);
        }
        Util.arrayCopyNonAtomic(bArray, bOff, crc16, (short) 0, bLen);
    }

    @Override
    public short doFinal(byte[] inBuff, short inOffset, short inLength, byte[] outBuff, short outOffset) {
        update(inBuff, inOffset, inLength);
        short temp = Util.getShort(crc16, (short) 0);
        temp = (short) (~temp);
        Util.setShort(crc16, (short) 0, temp);
        Util.arrayCopy(crc16, (short) 0, outBuff, outOffset, LENGTH);
        Util.arrayFillNonAtomic(crc16, (short) 0, LENGTH, (byte) 0);
        return LENGTH;
    }

    @Override
    public void update(byte[] inBuff, short inOffset, short inLength) {
        crc16(inBuff, inOffset, inLength);
    }

    private void crc16(byte[] inBuf, short inOff, short inLen) {
        short fcs = Util.getShort(crc16, (short) 0);
        for (short i = inOff; i < (short) (inOff + inLen); i++) {
            short d = (short) (inBuf[i] << 8);
            for (short k = 0; k < 8; k++) {
                if ((short) ((fcs ^ d) & 0x8000) != 0) {
                    fcs = (short) ((short) (fcs << 1) ^ 0x1021);
                } else {
                    fcs <<= 1;
                }
                d <<= 1;
            }

        }
        Util.setShort(crc16, (short) 0, fcs);
    }
}
