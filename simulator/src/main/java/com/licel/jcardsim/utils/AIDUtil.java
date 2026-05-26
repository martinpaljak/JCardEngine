// SPDX-FileCopyrightText: 2014 Robert Bachmann
// SPDX-License-Identifier: Apache-2.0
package com.licel.jcardsim.utils;

import apdu4j.core.CommandAPDU;
import javacard.framework.AID;
import javacard.framework.ISO7816;
import org.bouncycastle.util.encoders.Hex;

import java.util.Arrays;
import java.util.Comparator;
import java.util.Objects;

/**
 * Utility methods for dealing with AIDs.
 */
public final class AIDUtil {
    private static final Comparator<AID> aidComparator = (aid1, aid2) -> {
        String s1 = aid1 != null ? aid1.toString() : "";
        String s2 = aid2 != null ? aid2.toString() : "";
        return s1.compareTo(s2);
    };

    /**
     * Generate the raw bytes of a SELECT APDU for <code>aid</code>.
     *
     * @param aid AID to be selected
     * @return SELECT APDU bytes (CLA=0x00, INS=0xA4, P1=0x04, P2=0x00, Lc, AID, Le=0x00)
     * @throws java.lang.NullPointerException if <code>aid</code> is null
     */
    public static byte[] selectBytes(AID aid) {
        Objects.requireNonNull(aid);

        byte[] bytes = bytes(aid);
        byte[] selectCmd = new byte[bytes.length + ISO7816.OFFSET_CDATA + 1];
        selectCmd[ISO7816.OFFSET_CLA] = ISO7816.CLA_ISO7816;
        selectCmd[ISO7816.OFFSET_INS] = ISO7816.INS_SELECT;
        selectCmd[ISO7816.OFFSET_P1] = 0x04;
        selectCmd[ISO7816.OFFSET_P2] = 0x00;
        selectCmd[ISO7816.OFFSET_LC] = (byte) bytes.length;
        System.arraycopy(bytes, 0, selectCmd, ISO7816.OFFSET_CDATA, bytes.length);
        selectCmd[selectCmd.length - 1] = 0;

        return selectCmd;
    }

    /**
     * Generate a SELECT APDU for <code>aid</code>.
     *
     * @param aid AID to be selected
     * @return SELECT CommandAPDU (CLA=0x00, INS=0xA4, P1=0x04, P2=0x00, Lc, AID, Le=0x00)
     * @throws java.lang.NullPointerException if <code>aid</code> is null
     */
    public static CommandAPDU select(AID aid) {
        return new CommandAPDU(selectBytes(aid));
    }

    /**
     * Create an AID from a byte array
     *
     * @param aidBytes AID bytes
     * @return aid
     * @throws java.lang.NullPointerException     if <code>aidBytes</code> is null
     * @throws java.lang.IllegalArgumentException if <code>aidBytes.length</code> is incorrect
     */
    public static AID create(byte[] aidBytes) {
        Objects.requireNonNull(aidBytes);
        if (aidBytes.length < 5 || aidBytes.length > 16) {
            throw new IllegalArgumentException("AID size must be between 5 and 16 but was " + aidBytes.length);
        }
        return new AID(aidBytes, (short) 0, (byte) aidBytes.length);
    }

    /**
     * Create an AID from a byte array
     *
     * @param aidString AID bytes as hex string
     * @return aid
     * @throws java.lang.NullPointerException     if <code>aidString</code> is null
     * @throws java.lang.IllegalArgumentException if length is incorrect
     */
    public static AID create(String aidString) {
        Objects.requireNonNull(aidString);
        return create(Hex.decode(aidString));
    }

    public static byte[] bytes(AID aid) {
        byte[] buffer = new byte[16];
        short len = aid.getBytes(buffer, (short) 0);
        return Arrays.copyOf(buffer, len);
    }

    /**
     * @return a Comparator for AIDs
     */
    public static Comparator<AID> comparator() {
        return aidComparator;
    }

    private AIDUtil() {
    }
}
